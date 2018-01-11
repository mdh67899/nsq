package nsqd

// BackendQueue represents the behavior for the secondary message
// storage system
type BackendQueue interface {
	//将数据塞到队列里面
	Put([]byte) error
	//暴露一个chan, 从chan中读取队列里面的数据
	ReadChan() chan []byte // this is expected to be an *unbuffered* channel
	//关闭队列, 但是队列本身和队列读, 写的文件还存在, 可以继续读
	Close() error
	//删除队列, 但是队列还存在
	Delete() error
	//队列的读的位置和写的位置的距离
	Depth() int64
	//删掉队列所有的数据, 包括读位置和写位置所有的数据
	Empty() error
}
