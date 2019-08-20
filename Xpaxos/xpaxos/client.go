package xpaxos

// RPC handlers for an XPaxos client server (propose)
//
// client := MakeClient(replicas) - Creates an XPaxos client server
// => Option to perform cleanup with xp.Kill()

import (
	"time"

	"../network"
)

//
// ---------------------------- REPLICATE/REPLY RPC ---------------------------
//
func (client *Client) sendReplicate(server int, request ClientRequest, reply *Reply) bool {
	dPrintf("Replicate: from client server (%d) to XPaxos server (%d)\n", CLIENT, server)

	// clien远程调用第server个服务器的Replicate，这个
	return client.replicas[server].Call("XPaxos.Replicate", request, reply, CLIENT)
}

// 每个server都会执行这个命令，如果不能执行，就尝试5次，
func (client *Client) issueReplicate(server int, request ClientRequest, replyCh chan bool, retry int) {
	reply := &Reply{}

	//因为远程调用网络的原因有的会调用失败有的会调用成功
	if ok := client.sendReplicate(server, request, reply); ok {
		//远程调用成功的那些只有leader会回复client
		if reply.Success == true { // Only the leader should reply to client server
			replyCh <- reply.Success
		}
	} else {
		if retry < RETRY {
			retry++
			go client.issueReplicate(server, request, replyCh, retry)
		}
	}
}

func (client *Client) Propose(op interface{}) { // For simplicity, we assume the client's proposal is correct
	var timer <-chan time.Time

	client.mu.Lock()
	request := ClientRequest{
		MsgType:   REPLICATE,
		Timestamp: client.timestamp,
		Operation: op,
		ClientId:  CLIENT}

	replyCh := make(chan bool)

	for server, _ := range client.replicas {
		//fmt.Println("----", server)
		// 除了client以外，clinet像所有的服务器发送这个命令
		if server != CLIENT {
			go client.issueReplicate(server, request, replyCh, 0)
		}
	}

	if WAIT == false {
		timer = time.NewTimer(TIMEOUT * time.Millisecond).C
	}

	// propose 一次我就++一次
	client.timestamp++
	client.mu.Unlock()

	select {
	case <-timer:
		iPrintf("Timeout: Client.Propose: client server (%d)\n", CLIENT)
	case <-replyCh:
		iPrintf("Success: committed request (%d)\n", client.timestamp)
	case <-client.vcCh:
		iPrintf("Success: committed request after view change (%d)", client.timestamp)
	}
}

func (client *Client) ConfirmVC(msg Message, reply *Reply) {
	client.vcCh <- true
}

//
// ------------------------------- MAKE FUNCTION ------------------------------
//
func MakeClient(replicas []*network.ClientEnd) *Client {
	client := &Client{}

	client.mu.Lock()
	client.replicas = replicas
	client.timestamp = 0
	client.vcCh = make(chan bool)
	client.mu.Unlock()

	return client
}

func (client *Client) Kill() {}
