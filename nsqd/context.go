package nsqd

//很巧妙的一种方式: Topic和Channel处理数据的时候, 需要用到nsqd本身的一些信息, 调用的时候将nsqd写到结构体上下文中, 减少一下开销并增加代码的可读性
type context struct {
	nsqd *NSQD
}
