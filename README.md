# J4h3c
基于Java pcap编程，提供跨平台的h3c 802.1x的认证客户端，方便快速移植于各种环境下。

命令行形式
* 参数1-用户名
* 参数2-密码

## 为什么不用iNode
* 体积庞大
* 在用户目录记录日志文件，增加CPU负载，减少硬盘寿命
* 经常莫名错误
* 支持平台少

## 下载
J4h3c：[下载地址](https://github.com/XJhrack/J4h3c/releases)

使用方法，编辑run.bat
替换用户名与密码 运行
选择有线网卡完成认证

命令行：java -jar SchoolAuth.jar 用户名 密码

## 依赖开发环境
* Linux/openWRT: libpcap
* Windows: WinPcap

## 附加说明
目前只负责认证，认证成功后需手动发起dhcp获取ip
后续添加自动获取功能

## 感谢
* [H3C](https://github.com/QCute/H3C)
* [Pcap4J](https://github.com/kaitoy/pcap4j)

## 参考
[伯克利包过滤语法](https://www.winpcap.org/docs/docs_40_2/html/group__language.html)(Berkeley Packet Filter,BPF)
