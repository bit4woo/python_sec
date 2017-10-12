### 代码注入、命令执行

1.内置危险函数

	exec
	execfile
	eval
2.标准库危险模块

	os
	sys
	subprocess
	commands
3.危险第三方库
	Template(user_input) : 模板注入(SSTI)所产生的代码执行
	subprocess32 
4.反序列化相关库
	marshal
	PyYAML
	pickle和cpickle
	shelve
	PIL
	unzip


参考：

[Python沙箱逃逸的n种姿势](https://xianzhi.aliyun.com/forum/read/2138.html)

[Python之数据序列化（json、pickle、shelve）](http://www.cnblogs.com/yyds/p/6563608.html)

[Exploiting Python PIL Module Command Execution Vulnerability](https://xianzhi.aliyun.com/forum/read/2163.html)

[Exploiting Python Code Injection in Web Applications](https://www.doyler.net/security-not-included/exploiting-python-code-injection)

[EXPLOITING PYTHON CODE INJECTION IN WEB APPLICATIONS](http://www.securitynewspaper.com/2016/11/12/exploiting-python-code-injection-web-applications/)

[Exploiting Python Code Injection in Web Applications](https://sethsec.blogspot.jp/2016/11/exploiting-python-code-injection-in-web.html)