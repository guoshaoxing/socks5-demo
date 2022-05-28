# socks5-demo

终端输入
```shell
go run main.go
```
起一个代理，

另外一个终端输入
```shell
curl -v --proxy socks5://localhost:1080 www.baidu.com
```
进行代理访问
