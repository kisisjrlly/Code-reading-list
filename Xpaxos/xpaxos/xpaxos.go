package xpaxos

// RPC handlers for the XPaxos common case (replicate, prepare, commit, reply)
// XPaxos operates under a system model called Cross Fault-Tolerance (XFT) that lies
// between Crash Fault-Tolerance (CFT) and Byzantine Fault-Tolerance (BFT)
//
// XFT Assumptions:
// (1) Clients and replicas can suffer Byzantine faults
// (2) All replicas share reliable bi-directional communication channels
// (3) An *eventually synchronous* network model (i.e. there always exists a majority
//     of replicas - a synchronous group - that can send RPCs within some time frame
//     delta)
//
// We simulate a network in the eponymous package - in particular, this allows gives us
// fine-grained control over the time frame delta (defined in network/common.go - line 9)
//
// xp := Make(replicas, id, privateKey, publicKeys) - Creates an XPaxos server
// => Option to perform cleanup with xp.Kill()

import (
	"bytes"
	"crypto/rsa"
	"math/rand"
	"time"

	"../network"
)

//
// ---------------------------- REPLICATE/REPLY RPC ---------------------------
//
//
func (xp *XPaxos) Replicate(request ClientRequest, reply *Reply) {
	// By default reply.IsLeader = false and reply.Success = false
	xp.mu.Lock()
	//这个request只是客户端的request
	//生成的摘要也只是客户端request的摘要
	msgDigest := digest(request)

	//生成的签名只是本xp对客户端的摘要的签名
	signature := xp.sign(msgDigest)
	reply.MsgDigest = msgDigest
	reply.Signature = signature

	//每个server都会执行这个函数，但是只有leader才能发起prepare，leader之外的见else
	if xp.id == xp.getLeader() { // If XPaxos server is the leader
		reply.IsLeader = true

		if len(xp.prepareLog) > 0 && request.Timestamp <= xp.prepareLog[len(xp.prepareLog)-1].Msg0.ClientTimestamp {
			xp.mu.Unlock()
			reply.Success = true
			return
		}

		xp.prepareSeqNum++

		// leader包装的消息，并没有重新进行生成摘要和签名
		msg := Message{ // Leader's prepare message
			MsgType:         PREPARE,
			MsgDigest:       msgDigest,
			Signature:       signature,
			PrepareSeqNum:   xp.prepareSeqNum,
			View:            xp.view,
			ClientTimestamp: request.Timestamp,
			// 这个id就是leader的ID
			SenderId: xp.id}
		//把client的request原文和把xp（leader）生成request的签名和和摘要以及其他的信息放在了prepareLog中
		prepareEntry := xp.appendToPrepareLog(request, msg)

		msgMap := make(map[int]Message, 0)
		xp.appendToCommitLog(request, msg, msgMap)

		numReplies := len(xp.synchronousGroup) - 1
		replyCh := make(chan bool, numReplies)

		for server, _ := range xp.synchronousGroup {
			//leader向同步组的其他所有的server发送prepare消息，不包括我自己，因此，本xp.prepare都是处理别人发过来的prepare消息。。。
			if server != xp.id {
				go xp.issuePrepare(server, prepareEntry, replyCh)
			}
		}

		xp.mu.Unlock()

		timer := time.NewTimer(3 * network.DELTA * time.Millisecond).C

		//用于检测同步组中的服务器是否有的超时回应，因为要求同步组。。。
		for i := 0; i < numReplies; i++ {
			select {
			case <-timer:
				dPrintf("Timeout: XPaxos.Replicate: XPaxos server (%d)\n", xp.id)
				return
			case <-replyCh:
			}
		}

		xp.mu.Lock()
		if xp.view != msg.View {
			xp.mu.Unlock()
			return
		}

		xp.executeSeqNum++
		reply.Success = true
	} else {
		// 如果不是leader，那么就去ping leader，这里是不光同步组内的需要ping leader？作者好像让follower和active都在ping leader，也没错，就是要求严格了一点。。。
		go xp.issuePing(xp.getLeader(), xp.view)
	}
	xp.mu.Unlock()
}

//
// -------------------------------- PREPARE RPC -------------------------------
//
func (xp *XPaxos) sendPrepare(server int, prepareEntry PrepareLogEntry, reply *Reply) bool {

	// prepareEntry包含两部分，一部分是client的明文 request，另一部分是经过本xp组装的一些消息，本xp在向其他的xerver发送prepare消息时可能会修改本xp组装的那些消息
	if xp.byzantine == true {
		for i := len(prepareEntry.Msg0.Signature) - 1; i > 0; i-- {
			j := rand.Intn(i + 1)
			prepareEntry.Msg0.Signature[i], prepareEntry.Msg0.Signature[j] = prepareEntry.Msg0.Signature[j], prepareEntry.Msg0.Signature[i]
		}
	}

	dPrintf("Prepare: from XPaxos server (%d) to XPaxos server (%d)\n", xp.id, server)
	return xp.replicas[server].Call("XPaxos.Prepare", prepareEntry, reply, xp.id)
}

// 本xp向其他的 server发送消息
func (xp *XPaxos) issuePrepare(server int, prepareEntry PrepareLogEntry, replyCh chan bool) {
	reply := &Reply{}

	if ok := xp.sendPrepare(server, prepareEntry, reply); ok {
		xp.mu.Lock()
		if xp.view != prepareEntry.Msg0.View {
			xp.mu.Unlock()
			return
		}
		// 还需要reply？
		// 这个验证是验证prepare消息中的reply的摘要和签名？验证一下第server的回应是否被篡改？
		// 本人感觉这个reply没有事吧。。。
		verification := xp.verify(server, reply.MsgDigest, reply.Signature)

		if bytes.Compare(prepareEntry.Msg0.MsgDigest[:], reply.MsgDigest[:]) == 0 && verification == true {
			if reply.Success == true {
				replyCh <- reply.Success
			} else if reply.Suspicious == true {
				//这要是怀疑。。。就等着Replicate函数里面的超时探测吗
				xp.mu.Unlock()
				return
			}
		} else { // Verification of crypto signature in reply fails
			go xp.issueSuspect(xp.view)
		}
		xp.mu.Unlock()
	} else { // RPC times out after time frame delta (see network)
		// 也就是说对第sever的远程调用失败了，证明同步组不同步了。。。
		go xp.issueSuspect(prepareEntry.Msg0.View)
	}
}

// 本xp处理来自 leader 的prepare消息，别人不会给我发PrepareEntry
// 注意xpaxos是两阶段，client向 leader发送 request，leader向 follwer发送prepare，所有的follower像其他的follower发送commit
// leader发送给followerprepare消息，还需要follower回应吗？
func (xp *XPaxos) Prepare(prepareEntry PrepareLogEntry, reply *Reply) {
	// By default reply.Success = false and reply.Suspicious = false
	xp.mu.Lock()

	// 只是client request的摘要
	msgDigest := digest(prepareEntry.Request)

	//这里重新签名了，但是也只对client的request的做了签名
	signature := xp.sign(msgDigest)
	reply.MsgDigest = msgDigest
	reply.Signature = signature

	//本xp的视图和发给我prepareEntry的那个服务器的视图编号得一样
	if xp.view != prepareEntry.Msg0.View {
		xp.mu.Unlock()
		return
	}

	// 最开始时肯定是本xp.prepareSeqNum=0，
	// prepareEntry.Msg0.MsgDigest[:]也是clinet request 的摘要，只要发给我的那个server没有做比特反转，那么就没变，
	// 同理prepareEntry.Msg0.Signature代表发给本xp的服务器对client request生成摘要的签名，只要，发给本xp的那个SenderId没有做比特翻转，这里的verify便是对的。。。
	if prepareEntry.Msg0.PrepareSeqNum == xp.prepareSeqNum+1 && bytes.Compare(prepareEntry.Msg0.MsgDigest[:],
		msgDigest[:]) == 0 && xp.verify(prepareEntry.Msg0.SenderId, msgDigest, prepareEntry.Msg0.Signature) == true {
		if len(xp.prepareLog) > 0 && prepareEntry.Request.Timestamp <= xp.prepareLog[len(xp.prepareLog)-1].Msg0.ClientTimestamp {
			reply.Success = true
			xp.mu.Unlock()
			return
		}

		xp.prepareSeqNum++
		// 把从leader收到的prepareEntry添加到我自己的Log中
		xp.prepareLog = append(xp.prepareLog, prepareEntry)

		msg := Message{

			// 消息类型改成commite了。。。
			MsgType:       COMMIT,
			MsgDigest:     msgDigest,
			Signature:     signature,
			PrepareSeqNum: xp.prepareSeqNum,
			View:          xp.view,
			// 这个时间戳到现在还是propose（）里面的那个时间戳
			ClientTimestamp: prepareEntry.Request.Timestamp,
			// 这个id注意与leader 的id区别开
			SenderId: xp.id}

		if xp.executeSeqNum >= len(xp.commitLog) {
			msgMap := make(map[int]Message, 0)
			msgMap[xp.id] = msg                                                   // Follower's commit message
			xp.appendToCommitLog(prepareEntry.Request, prepareEntry.Msg0, msgMap) // Leader's prepare message is prepareEntry.Msg0
		}

		numReplies := len(xp.synchronousGroup) - 1
		replyCh := make(chan bool, numReplies)

		for server, _ := range xp.synchronousGroup {
			if server != xp.id {

				// 同步组内所有的server包括leader都发送提交
				go xp.issueCommit(server, msg, replyCh)
			}
		}
		xp.mu.Unlock()

		timer := time.NewTimer(3 * network.DELTA * time.Millisecond).C

		// 如果时间超时重试三次
		for i := 0; i < numReplies; i++ {
			select {
			case <-timer:
				dPrintf("Timeout: XPaxos.Prepare: XPaxos server (%d)\n", xp.id)
				return
			case <-replyCh:
			}
		}

		timer = time.NewTimer(3 * network.DELTA * time.Millisecond).C

		// Busy wait until XPaxos server receives commit messages from entire synchronous group
		// 直到本xp收到了其他server的所有commit消息，否则将一直堵塞
		xp.mu.Lock()
		for xp.executeSeqNum < len(xp.commitLog) && len(xp.commitLog[xp.executeSeqNum].Msg1) != len(xp.synchronousGroup)-1 {
			xp.mu.Unlock()
			select {
			case <-timer:
				dPrintf("Timeout: XPaxos.Prepare: XPaxos server (%d)\n", xp.id)
				return
			default:
				time.Sleep(10 * time.Millisecond)
			}
			xp.mu.Lock()
		}

		if xp.view != msg.View {
			xp.mu.Unlock()
			return
		}

		xp.executeSeqNum++
		reply.Success = true
	} else { // Verification of crypto signature in prepareEntry fails

		// 签名验证失败，证明比特翻转。。。。
		reply.Suspicious = true
		go xp.issueSuspect(xp.view)
	}
	xp.mu.Unlock()
}

//
// --------------------------------- COMMIT RPC --------------------------------
//
func (xp *XPaxos) sendCommit(server int, msg Message, reply *Reply) bool {

	//follwer节点比特翻转，对整个要发送的发起commit消息进行了比特翻转
	if xp.byzantine == true {
		for i := len(msg.Signature) - 1; i > 0; i-- {
			j := rand.Intn(i + 1)
			msg.Signature[i], msg.Signature[j] = msg.Signature[j], msg.Signature[i]
		}
	}

	dPrintf("Commit: from XPaxos server (%d) to XPaxos server (%d)\n", xp.id, server)
	return xp.replicas[server].Call("XPaxos.Commit", msg, reply, xp.id)
}

func (xp *XPaxos) issueCommit(server int, msg Message, replyCh chan bool) {
	reply := &Reply{}

	if ok := xp.sendCommit(server, msg, reply); ok {
		xp.mu.Lock()
		if xp.view != msg.View {
			xp.mu.Unlock()
			return
		}

		verification := xp.verify(server, reply.MsgDigest, reply.Signature)

		if bytes.Compare(msg.MsgDigest[:], reply.MsgDigest[:]) == 0 && verification == true {
			if reply.Success == true {
				replyCh <- reply.Success
			} else if reply.Suspicious == true {
				xp.mu.Unlock()
				return
			} else {
				go xp.issueCommit(server, msg, replyCh) // Retransmit if commit RPC fails - DO NOT CHANGE
			}
		} else { // Verification of crypto signature in reply fails
			go xp.issueSuspect(xp.view)
		}
		xp.mu.Unlock()
	} else { // RPC times out after time frame delta (see network)
		// 远程调用失败，同步组不同步
		go xp.issueSuspect(msg.View)
	}
}

func (xp *XPaxos) Commit(msg Message, reply *Reply) {
	// By default reply.Success == false
	xp.mu.Lock()
	defer xp.mu.Unlock()

	msgDigest := msg.MsgDigest
	signature := xp.sign(msgDigest)
	reply.MsgDigest = msgDigest
	reply.Signature = signature

	// 本xp收到别人发给我的commit消息，如果那个人在发给我的时候比特翻转了，msg.View不就乱了？
	if xp.view != msg.View {
		reply.Suspicious = true
		return
	}

	if xp.verify(msg.SenderId, msgDigest, msg.Signature) == true {
		if xp.executeSeqNum < len(xp.commitLog) {
			senderId := msg.SenderId
			//这里才记录到commitLog中去。。。
			xp.commitLog[xp.executeSeqNum].Msg1[senderId] = msg
			reply.Success = true
		}
	} else { // Verification of crypto signature in msg fails
		reply.Suspicious = true
		go xp.issueSuspect(xp.view)
	}
}

//
// --------------------------------- PING RPC ---------------------------------
//
func (xp *XPaxos) sendPing(server int, view int, reply *Reply) bool {
	dPrintf("Ping: from XPaxos server (%d) to XPaxos server (%d)\n", xp.id, server)
	return xp.replicas[server].Call("XPaxos.Ping", view, reply, xp.id)
}

func (xp *XPaxos) issuePing(server int, view int) {
	reply := &Reply{}

	if ok := xp.sendPing(server, view, reply); ok {
		return
	} else {
		go xp.issueSuspect(view)
	}
}

func (xp *XPaxos) Ping(view int, reply *Reply) {
	return
}

//
// ------------------------------- MAKE FUNCTION ------------------------------
//
func Make(replicas []*network.ClientEnd, id int, privateKey *rsa.PrivateKey,
	publicKeys map[int]*rsa.PublicKey) *XPaxos {
	xp := &XPaxos{}

	xp.mu.Lock()
	xp.replicas = replicas
	xp.synchronousGroup = make(map[int]bool, 0)
	xp.id = id
	xp.view = 1
	xp.prepareSeqNum = 0
	xp.executeSeqNum = 0
	xp.prepareLog = make([]PrepareLogEntry, 0)
	xp.commitLog = make([]CommitLogEntry, 0)
	xp.privateKey = privateKey
	xp.publicKeys = publicKeys
	xp.suspectSet = make(map[[32]byte]SuspectMessage, 0)
	xp.vcSet = make(map[[32]byte]ViewChangeMessage, 0)
	xp.netFlag = false
	xp.netTimer = nil
	xp.vcFlag = false
	xp.vcTimer = nil
	xp.receivedVCFinal = make(map[int]map[[32]byte]ViewChangeMessage, 0)
	xp.vcInProgress = false
	xp.byzantine = false

	// Make时生成一个同步组，三次Make 会选择一个主，一个从，一个备份节点。。。Test1例子中1号节点为主，2号为从，3号为备份
	xp.generateSynchronousGroup(int64(xp.view))
	xp.mu.Unlock()

	return xp
}

func (xp *XPaxos) Kill() {}
