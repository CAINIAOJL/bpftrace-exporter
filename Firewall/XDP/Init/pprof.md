# CPU 分析	        /debug/pprof/profile	 默认采集 30s 的 CPU 使用情况
# 内存分析（Heap）	 /debug/pprof/heap	      当前内存分配情况
# Goroutine 分析	    /debug/pprof/goroutine	 所有活跃的 goroutine 堆栈
# 阻塞分析	        /debug/pprof/block	      阻塞操作的堆栈跟踪
# 互斥锁分析	        /debug/pprof/mutex	      互斥锁竞争的分析

# go tool pprof http://localhost:6060/debug/pprof/heap