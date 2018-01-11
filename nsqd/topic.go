package nsqd

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nsqio/go-diskqueue"
	"github.com/nsqio/nsq/internal/lg"
	"github.com/nsqio/nsq/internal/quantile"
	"github.com/nsqio/nsq/internal/util"
)

type Topic struct {
	// 64bit atomic vars need to be first for proper alignment on 32bit platforms
	//Topic收到并处理完成的msg数量
	messageCount uint64

	sync.RWMutex

	//topic名字
	name string
	//消费topic数据的channel map集合
	channelMap map[string]*Channel
	//topic本身对应的backend磁盘文件队列, 实现了Put(), ReadChan(), Close(), Delete(), Depth() ,Empty()等方法
	//一般情况下topic收到的数据是放到memoryMsgChan, messagePump()方法会把数据取出放到各个channel的backend中
	// 但是有可能出现messagePump()方法处理比较慢的情况, 所以Topic也启用backend做个缓冲，不要卡住用户发送msg到topic, 所以nsq实现不了顺序消费, 只能实现最终消费
	backend BackendQueue
	//内存chan，用来接收topic收到的数据，临时缓冲区
	memoryMsgChan chan *Message
	//topic退出chan
	exitChan chan int
	//如果消费topic数据的channe数量（新增消费channel或者消费channel关闭）发生变化，往这个chan里面发送signal，由messagePump()方法更新channel并且把对应关系持久话到磁盘上
	channelUpdateChan chan int
	//waitGroup用来保证该topic执行的messagePump() goroutine最终可以正常结束
	waitGroup util.WaitGroupWrapper
	//topic close或者exit时的标志位
	exitFlag  int32
	idFactory *guidFactory

	ephemeral bool
	//删除topic后对该topic执行的方法
	deleteCallback func(*Topic)
	//deleteCallback方法只允许执行一次
	deleter sync.Once

	//暂停topic,
	paused int32
	//topic暂停服务的chan
	pauseChan chan bool

	//存储topic所属的nsqd数据结构，上下文
	ctx *context
}

// Topic constructor
func NewTopic(topicName string, ctx *context, deleteCallback func(*Topic)) *Topic {
	t := &Topic{
		name:              topicName,
		channelMap:        make(map[string]*Channel),
		memoryMsgChan:     make(chan *Message, ctx.nsqd.getOpts().MemQueueSize),
		exitChan:          make(chan int),
		channelUpdateChan: make(chan int),
		ctx:               ctx,
		pauseChan:         make(chan bool),
		deleteCallback:    deleteCallback,
		idFactory:         NewGUIDFactory(ctx.nsqd.getOpts().ID),
	}

	if strings.HasSuffix(topicName, "#ephemeral") {
		t.ephemeral = true
		t.backend = newDummyBackendQueue()
	} else {
		//传递给backend的log handler
		dqLogf := func(level diskqueue.LogLevel, f string, args ...interface{}) {
			opts := ctx.nsqd.getOpts()
			lg.Logf(opts.Logger, opts.logLevel, lg.LogLevel(level), f, args...)
		}
		//Topic启用backend, 防止收到的数据过多，messagePump()慢造成memoryMsgChan塞满, 先把消息放入topic自身的backend里面，等待messagePump方法处理到各个channel的backend
		t.backend = diskqueue.New(
			topicName,
			ctx.nsqd.getOpts().DataPath,
			ctx.nsqd.getOpts().MaxBytesPerFile,
			int32(minValidMsgLength),
			int32(ctx.nsqd.getOpts().MaxMsgSize)+minValidMsgLength,
			ctx.nsqd.getOpts().SyncEvery,
			ctx.nsqd.getOpts().SyncTimeout,
			dqLogf,
		)
	}

	//对该topic收到的进行后台处理goroutine, 启用waitGroup
	t.waitGroup.Wrap(func() { t.messagePump() })

	//将Metadata信息持久化的硬盘上
	t.ctx.nsqd.Notify(t)

	return t
}

// Exiting returns a boolean indicating if this topic is closed/exiting
func (t *Topic) Exiting() bool {
	return atomic.LoadInt32(&t.exitFlag) == 1
}

// GetChannel performs a thread safe operation
// to return a pointer to a Channel object (potentially new)
// for the given Topic
func (t *Topic) GetChannel(channelName string) *Channel {
	t.Lock()
	channel, isNew := t.getOrCreateChannel(channelName)
	t.Unlock()

	if isNew {
		// update messagePump state
		select {
		//如果channel是新增的, 持久化一下metaData到硬盘, 放入chan一个数据, 由messagePump()方法处理持久化操作
		case t.channelUpdateChan <- 1:
		case <-t.exitChan:
		}
	}

	return channel
}

//检查是该channel是否存在, 存在就返回, 没有就创建一个
// this expects the caller to handle locking
func (t *Topic) getOrCreateChannel(channelName string) (*Channel, bool) {
	channel, ok := t.channelMap[channelName]
	if !ok {
		//channel的Callback方法，如果channel关闭, 就执行callback方法从channnelMap中删掉channel和channel相关信息
		//总感觉怪怪的
		deleteCallback := func(c *Channel) {
			t.DeleteExistingChannel(c.name)
		}
		channel = NewChannel(t.name, channelName, t.ctx, deleteCallback)
		t.channelMap[channelName] = channel
		t.ctx.nsqd.logf(LOG_INFO, "TOPIC(%s): new channel(%s)", t.name, channel.name)
		return channel, true
	}
	return channel, false
}

func (t *Topic) GetExistingChannel(channelName string) (*Channel, error) {
	t.RLock()
	defer t.RUnlock()
	channel, ok := t.channelMap[channelName]
	if !ok {
		return nil, errors.New("channel does not exist")
	}
	return channel, nil
}

// DeleteExistingChannel removes a channel from the topic only if it exists
func (t *Topic) DeleteExistingChannel(channelName string) error {
	t.Lock()
	channel, ok := t.channelMap[channelName]
	if !ok {
		t.Unlock()
		return errors.New("channel does not exist")
	}
	delete(t.channelMap, channelName)
	// not defered so that we can continue while the channel async closes
	numChannels := len(t.channelMap)
	t.Unlock()

	t.ctx.nsqd.logf(LOG_INFO, "TOPIC(%s): deleting channel %s", t.name, channel.name)

	// delete empties the channel before closing
	// (so that we dont leave any messages around)
	channel.Delete()

	// update messagePump state
	select {
	case t.channelUpdateChan <- 1:
	case <-t.exitChan:
	}

	if numChannels == 0 && t.ephemeral == true {
		go t.deleter.Do(func() { t.deleteCallback(t) })
	}

	return nil
}

// PutMessage writes a Message to the queue
func (t *Topic) PutMessage(m *Message) error {
	t.RLock()
	defer t.RUnlock()
	if atomic.LoadInt32(&t.exitFlag) == 1 {
		return errors.New("exiting")
	}
	err := t.put(m)
	if err != nil {
		return err
	}
	atomic.AddUint64(&t.messageCount, 1)
	return nil
}

// PutMessages writes multiple Messages to the queue
func (t *Topic) PutMessages(msgs []*Message) error {
	t.RLock()
	defer t.RUnlock()
	if atomic.LoadInt32(&t.exitFlag) == 1 {
		return errors.New("exiting")
	}
	for _, m := range msgs {
		err := t.put(m)
		if err != nil {
			return err
		}
	}
	atomic.AddUint64(&t.messageCount, uint64(len(msgs)))
	return nil
}

func (t *Topic) put(m *Message) error {
	select {
	//尝试把msg放入topic的memoryMsgChan, 如果memoryMsgChan满了造成阻塞, 就放入topic的backend文件队列
	case t.memoryMsgChan <- m:
	default:
		b := bufferPoolGet()
		err := writeMessageToBackend(b, m, t.backend)
		bufferPoolPut(b)
		t.ctx.nsqd.SetHealth(err)
		if err != nil {
			t.ctx.nsqd.logf(LOG_ERROR,
				"TOPIC(%s) ERROR: failed to write message to backend - %s",
				t.name, err)
			return err
		}
	}
	return nil
}

func (t *Topic) Depth() int64 {
	//Depth返回topic memoryMsgChan缓冲区和backend文件队列堆积的数据，针对的是topic级别
	return int64(len(t.memoryMsgChan)) + t.backend.Depth()
}

// messagePump selects over the in-memory and backend queue and
// writes messages to every channel for this topic
func (t *Topic) messagePump() {
	var msg *Message
	var buf []byte
	var err error
	var chans []*Channel
	var memoryMsgChan chan *Message
	var backendChan chan []byte

	t.RLock()
	for _, c := range t.channelMap {
		//将消费topic数据的channel放到集合里面
		chans = append(chans, c)
	}
	t.RUnlock()

	if len(chans) > 0 {
		//如果有channel存在, 就处理topic收到的数据, 否则职位默认值nil, 什么都不处理, 等Topic的memoryMsgChan满了就由put方法放入到文件队列
		memoryMsgChan = t.memoryMsgChan
		backendChan = t.backend.ReadChan()
	}

	for {
		select {
		//topic的memoryMsgChan缓冲区收到的msg
		case msg = <-memoryMsgChan:
		//topic文件缓冲队列的未处理的msg
		case buf = <-backendChan:
			msg, err = decodeMessage(buf)
			if err != nil {
				t.ctx.nsqd.logf(LOG_ERROR, "failed to decode message - %s", err)
				continue
			}
		//topic的channel数量发生变化了, chan收到更新请求
		//更新metaData到硬盘, 并且更新自己的数据来源处理到channel的backend文件队列
		case <-t.channelUpdateChan:
			chans = chans[:0]
			t.RLock()
			for _, c := range t.channelMap {
				chans = append(chans, c)
			}
			t.RUnlock()
			if len(chans) == 0 || t.IsPaused() {
				memoryMsgChan = nil
				backendChan = nil
			} else {
				memoryMsgChan = t.memoryMsgChan
				backendChan = t.backend.ReadChan()
			}
			continue
		//暂停处理, 不再把msg放入到channel中
		case pause := <-t.pauseChan:
			if pause || len(chans) == 0 {
				memoryMsgChan = nil
				backendChan = nil
			} else {
				memoryMsgChan = t.memoryMsgChan
				backendChan = t.backend.ReadChan()
			}
			continue
		case <-t.exitChan:
			goto exit
		}

		for i, channel := range chans {
			chanMsg := msg
			// copy the message because each channel
			// needs a unique instance but...
			// fastpath to avoid copy if its the first channel
			// (the topic already created the first copy)
			if i > 0 {
				chanMsg = NewMessage(msg.ID, msg.Body)
				chanMsg.Timestamp = msg.Timestamp
				chanMsg.deferred = msg.deferred
			}
			if chanMsg.deferred != 0 {
				channel.PutMessageDeferred(chanMsg, chanMsg.deferred)
				continue
			}
			err := channel.PutMessage(chanMsg)
			if err != nil {
				t.ctx.nsqd.logf(LOG_ERROR,
					"TOPIC(%s) ERROR: failed to put msg(%s) to channel(%s) - %s",
					t.name, msg.ID, channel.name, err)
			}
		}
	}

exit:
	t.ctx.nsqd.logf(LOG_INFO, "TOPIC(%s): closing ... messagePump", t.name)
}

// Delete empties the topic and all its channels and closes
func (t *Topic) Delete() error {
	return t.exit(true)
}

// Close persists all outstanding topic data and closes all its channels
func (t *Topic) Close() error {
	return t.exit(false)
}

func (t *Topic) exit(deleted bool) error {
	//设置exitFlag, 线程级别安全性
	if !atomic.CompareAndSwapInt32(&t.exitFlag, 0, 1) {
		return errors.New("exiting")
	}

	if deleted {
		t.ctx.nsqd.logf(LOG_INFO, "TOPIC(%s): deleting", t.name)

		// since we are explicitly deleting a topic (not just at system exit time)
		// de-register this from the lookupd
		t.ctx.nsqd.Notify(t)
	} else {
		t.ctx.nsqd.logf(LOG_INFO, "TOPIC(%s): closing", t.name)
	}

	//关闭Topic的exitChan, 让Topic中所有的正在进行操作的goroutine结束
	//停止messagePump()方法, 不再从memoryMsgChan和backend文件队列的msg放到channel的backend队列里
	close(t.exitChan)

	// synchronize the close of messagePump()
	t.waitGroup.Wait()

	//如果是删除, 清空Topic的memoryMsgChan和文件队列的数据, 删除Topic的backend文件队列
	if deleted {
		t.Lock()
		for _, channel := range t.channelMap {
			delete(t.channelMap, channel.name)
			channel.Delete()
		}
		t.Unlock()

		// empty the queue (deletes the backend files, too)
		t.Empty()
		return t.backend.Delete()
	}

	//如果是关闭Topic, 把channel Close掉
	// close all the channels
	for _, channel := range t.channelMap {
		err := channel.Close()
		if err != nil {
			// we need to continue regardless of error to close all the channels
			t.ctx.nsqd.logf(LOG_ERROR, "channel(%s) close - %s", channel.name, err)
		}
	}

	// write anything leftover to disk
	t.flush()
	return t.backend.Close()
}

//清空Topic的memoryMsgChan数据, 关闭文件队列中的数据处理(但是文件队列的readFile, writeFile, readPos, writePos信息还在)
func (t *Topic) Empty() error {
	for {
		select {
		case <-t.memoryMsgChan:
		default:
			goto finish
		}
	}

finish:
	return t.backend.Empty()
}

//关闭Topic时将Topic的memoryMsgChan里的数据全部持久化到backend文件队列
func (t *Topic) flush() error {
	var msgBuf bytes.Buffer

	if len(t.memoryMsgChan) > 0 {
		t.ctx.nsqd.logf(LOG_INFO,
			"TOPIC(%s): flushing %d memory messages to backend",
			t.name, len(t.memoryMsgChan))
	}

	for {
		select {
		case msg := <-t.memoryMsgChan:
			err := writeMessageToBackend(&msgBuf, msg, t.backend)
			if err != nil {
				t.ctx.nsqd.logf(LOG_ERROR,
					"ERROR: failed to write message to backend - %s", err)
			}
		default:
			goto finish
		}
	}

finish:
	return nil
}

//没看懂,,,,,,后期再补充
func (t *Topic) AggregateChannelE2eProcessingLatency() *quantile.Quantile {
	var latencyStream *quantile.Quantile
	t.RLock()
	realChannels := make([]*Channel, 0, len(t.channelMap))
	for _, c := range t.channelMap {
		realChannels = append(realChannels, c)
	}
	t.RUnlock()
	for _, c := range realChannels {
		if c.e2eProcessingLatencyStream == nil {
			continue
		}
		if latencyStream == nil {
			latencyStream = quantile.New(
				t.ctx.nsqd.getOpts().E2EProcessingLatencyWindowTime,
				t.ctx.nsqd.getOpts().E2EProcessingLatencyPercentiles)
		}
		latencyStream.Merge(c.e2eProcessingLatencyStream)
	}
	return latencyStream
}

func (t *Topic) Pause() error {
	return t.doPause(true)
}

func (t *Topic) UnPause() error {
	return t.doPause(false)
}

func (t *Topic) doPause(pause bool) error {
	//停止和唤醒队列, 根据传递的值来通知messagePump()方法, 停止就干掉messagePump()方法里读取的memoryMsgChan
	//和backend文件队列, 不再继续处理Topic收到的数据发送到各个channel的backend队列
	if pause {
		atomic.StoreInt32(&t.paused, 1)
	} else {
		atomic.StoreInt32(&t.paused, 0)
	}

	select {
	case t.pauseChan <- pause:
	case <-t.exitChan:
	}

	return nil
}

func (t *Topic) IsPaused() bool {
	return atomic.LoadInt32(&t.paused) == 1
}

func (t *Topic) GenerateID() MessageID {
retry:
	id, err := t.idFactory.NewGUID()
	if err != nil {
		time.Sleep(time.Millisecond)
		goto retry
	}
	return id.Hex()
}
