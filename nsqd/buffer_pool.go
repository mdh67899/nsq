package nsqd

import (
	"bytes"
	"sync"
)

//Topic和Channel中将消息写入到文件的时候都是将消息encoding成二进制, 都是利用bytes.Buffer类型做转换介质, 此处加一个bytes.Buffer pool, 减少频繁生成对象造成的gc开销
var bp sync.Pool

func init() {
	bp.New = func() interface{} {
		return &bytes.Buffer{}
	}
}

func bufferPoolGet() *bytes.Buffer {
	return bp.Get().(*bytes.Buffer)
}

func bufferPoolPut(b *bytes.Buffer) {
	bp.Put(b)
}
