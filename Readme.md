代码注入、命令执行

1.内置危险函数

	exec
	execfile
	eval
[Python eval的常见错误封装及利用原理](http://xxlegend.com/2015/07/31/Python%20eval%E7%9A%84%E5%B8%B8%E8%A7%81%E9%94%99%E8%AF%AF%E5%B0%81%E8%A3%85%E5%8F%8A%E5%88%A9%E7%94%A8%E5%8E%9F%E7%90%86/)
[Exploiting Python’s Eval](http://www.floyd.ch/?p=584)

2.标准库危险模块

	os
	sys
	subprocess
	commands
3.危险第三方库
	Template(user_input) : 模板注入(SSTI)所产生的代码执行
	subprocess32 
4.反序列化
	marshal
	PyYAML
	pickle和cpickle
	shelve
	PIL
	unzip
参考：

[Python之数据序列化（json、pickle、shelve）](http://www.cnblogs.com/yyds/p/6563608.html)

[Exploiting Python PIL Module Command Execution Vulnerability](https://xianzhi.aliyun.com/forum/read/2163.html)



payload构造

	前提
		eval+compile
			多语句
		__import__
			__import__是一个函数，并且只接受字符串参数，import 都是在它的基础上实现的。
		importlib
参考
	import相关，沙箱绕过
		https://xianzhi.aliyun.com/forum/read/2138.html
	代码注入
		https://www.doyler.net/security-not-included/exploiting-python-code-injection
		http://www.securitynewspaper.com/2016/11/12/exploiting-python-code-injection-web-applications/
		https://sethsec.blogspot.jp/2016/11/exploiting-python-code-injection-in-web.html
codereview
	Python Security Auditing (IV): Command Execution
		https://www.cdxy.me/?p=747
