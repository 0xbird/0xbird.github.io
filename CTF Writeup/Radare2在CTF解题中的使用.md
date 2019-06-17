题目下载地址：

https://github.com/Maijin/Workshop2015/tree/master/IOLI-crackme

## Crackme 0x00

![1560429470509](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560429470509.png)

### Method 1

Maybe the password is a strings so use `strings` to find it.

![1560429517089](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560429517089.png)

There is a strange number `250382`, try it.

![1560429577505](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560429577505.png)

Or, use `rabin2`, the “binary program info extractor” from radare2.

![1560429629022](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560429629022.png)

`-z` *let you get strings (from data section)*

### Method 2

Modify the program logic so that any password can be OK.

I opened the binary with `radare2` using `-w` to be in *write* mode, allowing radare2 to write data to the file.

> `s` lets you seek to an address (or symbol)
>
> `pd #` lets you print disassembly of # instructions (from current seek)

Above is the disassembly output of the `main` function. I found the function at `0x08048470` is a conditionally jump `je`, so we change it to `jmp`, which is an unconditionally jump.

![1560429919326](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560429919326.png)

![1560429954945](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560429954945.png)

> `wx` is short for Write heX, and allows for writing raw bytes to an offset specificly.

Now we can get successful message whatever the password is.

![1560430057482](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560430057482.png)

## Crackme0x01

This time, the method 1 below got failed.

![1560500837327](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560500837327.png)

So, lets see the code again.

![1560502011664](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560502011664.png)

> `aa` tells radare2 to analyse the whole binary.
>
> `pdf` is short of Print Disassemble Function

We also found a `je` at `0x08048432` and if we change it to `jmp`, it will be successful. But this time, we try another method to found its password. The function at `0x0804842b`is a `cmp` instruction, with a constant `0x149a`. The `0x149a` is a hexadecimal number and we can change it to others.

![1560502136145](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560502136145.png)

> The `?` command is used to perform math operations and returns the answer in a wide variety of formats.

Maybe the password is just one of them.

![1560502185736](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560502185736.png)

## Crackme0x02

This time also a “compare-jump” program, but the destination is “Invalid_Password__n” instead “Password_OK_”.

![1560505592151](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560505592151.png)

So, we can use a `nop` instruction to replace the jump instruction at `0x08048451`.

![1560505639794](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560505639794.png)

![1560505705540](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560505705540.png)

## Crackme0x03

The challenge becomes a little more difficult, there is no jump instruction.

![1560505763442](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560505763442.png)

We found a function called `sym.test`, let’s see the detail.

![1560505811886](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560505811886.png)

In the below disassembly code, there are two strings seems to be encrypted, just like `Invalid_Password__n` and `Password_OK_` we found before.

### Method 1

Of course, we can replace `je` to `cmp` at `0x0804847a` in function `sym.test`.

![1560505916178](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560505916178.png)

![1560505966755](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560505966755.png)

### Method 2

We focus on these lines in function `sym.main`, I have made some annotations.

```
|           0x080484df      c745f85a0000.  mov dword [local_8h], 0x5a  ; 'Z'
|           0x080484e6      c745f4ec0100.  mov dword [local_ch], 0x1ec
|           0x080484ed      8b55f4         mov edx, dword [local_ch]          ; edx = 0x1ec
|           0x080484f0      8d45f8         lea eax, dword [local_8h]          ; eax -> ebp-0x8
|           0x080484f3      0110           add dword [eax], edx               ; ebp-0x8 = (0x5a + 0x1ec)
|           0x080484f5      8b45f8         mov eax, dword [local_8h]          ; eax = 0x5a + 0x1ec = 0x246
|           0x080484f8      0faf45f8       imul eax, dword [local_8h]         ; eax = 0x246 * 0x246 = 0x52b24
|           0x080484fc      8945f4         mov dword [local_ch], eax          ; ebp-0xc = 0x52b24
|           0x080484ff      8b45f4         mov eax, dword [local_ch]          ; eax = 0x52b24
|           0x08048502      89442404       mov dword [local_4h_2], eax        ; esp+0x4 = eax
```

So, The value of `eax` is `0x52b24`, and in function `sym.test`:

```
|           0x08048474      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0
|           0x08048477      3b450c         cmp eax, dword [arg_ch]     ; [0xc:4]=0
```

Although we know the `eax` in `sym.main` is different from in `sym.test`. We just try password with the decimal value of `0x52b24`.

![1560506044416](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560506044416.png)

![1560506100805](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560506100805.png)

Oh, surprise!

From the name of functin `sym.shift`, I guess the encryption algorithm to be transposition cipher.

```
[0x08048360]> pdf @ sym.shift
/ (fcn) sym.shift 90
|   sym.shift (int arg_8h);
|           ; var int local_7ch @ ebp-0x7c
|           ; var int local_78h @ ebp-0x78
|           ; arg int arg_8h @ ebp+0x8
|           ; var int local_4h @ esp+0x4
|              ; CALL XREF from 0x08048491 (sym.test)
|              ; CALL XREF from 0x08048483 (sym.test)
|           0x08048414      55             push ebp
|           0x08048415      89e5           mov ebp, esp
|           0x08048417      81ec98000000   sub esp, 0x98
|           0x0804841d      c74584000000.  mov dword [local_7ch], 0
|              ; JMP XREF from 0x0804844e (sym.shift)
|       .-> 0x08048424      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0
|       |   0x08048427      890424         mov dword [esp], eax
|       |   0x0804842a      e811ffffff     call sym.imp.strlen        ; size_t strlen(const char *s)
|       |   0x0804842f      394584         cmp dword [local_7ch], eax  ; [0x13:4]=256
|      ,==< 0x08048432      731c           jae 0x8048450
|      ||   0x08048434      8d4588         lea eax, dword [local_78h]
|      ||   0x08048437      89c2           mov edx, eax
|      ||   0x08048439      035584         add edx, dword [local_7ch]
|      ||   0x0804843c      8b4584         mov eax, dword [local_7ch]
|      ||   0x0804843f      034508         add eax, dword [arg_8h]
|      ||   0x08048442      0fb600         movzx eax, byte [eax]
|      ||   0x08048445      2c03           sub al, 3
|      ||   0x08048447      8802           mov byte [edx], al
|      ||   0x08048449      8d4584         lea eax, dword [local_7ch]
|      ||   0x0804844c      ff00           inc dword [eax]
|      |`=< 0x0804844e      ebd4           jmp 0x8048424
|      `--> 0x08048450      8d4588         lea eax, dword [local_78h]
|           0x08048453      034584         add eax, dword [local_7ch]
|           0x08048456      c60000         mov byte [eax], 0
|           0x08048459      8d4588         lea eax, dword [local_78h]
|           0x0804845c      89442404       mov dword [local_4h], eax
|           0x08048460      c70424e88504.  mov dword [esp], 0x80485e8  ; [0x80485e8:4]=0xa7325 ; "%s."
|           0x08048467      e8e4feffff     call sym.imp.printf        ; int printf(const char *format)
|           0x0804846c      c9             leave
\           0x0804846d      c3             ret
```

Through the analysis, we can write the following script to decrypted.

```
In [1]: print(''.join([chr(ord(i)-0x3) for i in 'Sdvvzrug#RN$$$#=']))
Password OK!!! :)

In [2]: print(''.join([chr(ord(i)-0x3) for i in 'Lqydolg#Sdvvzrug$']))
Invalid Password!
```

## Crackme0x04

![1560506666760](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560506666760.png)

![1560506711034](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560506711034.png)

With the `man sscanf` command, we know that `sscanf()` reads its input from the character string pointed to by `str`.

```
int sscanf(const char *str, const char *format, ...);
```

The functin `strlen()` get the length of the password we input. Everytime function `sscanf()` get a character from our password as “`%s`”, and then transform it to “`%d`”. With the loop for *len* times, which *len* is the length of our password, these number add together, and compare with `0xf`(aka 15). If equals, jump to output the successful message.

![1560506877507](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560506877507.png)

## crackme0x05

![1560506927756](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560506927756.png)

![1560506954488](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560506954488.png)

![1560507019236](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560507019236.png)

This time, if we want to modify instructions to get success, there are three places need to modify, `0x080484ea`, `0x0804851e`, and `0x080484ac`.

Next, we use a normal method. Same function as the previous crackme, but this time, it’s not compared to 15, but to 16. And instead of a printf(“Password OK!”).

![1560507072724](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560507072724.png)

## crackme0x06

![1560507512695](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560507512695.png)

![1560507541277](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560507541277.png)

![1560507567602](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560507567602.png)

![1560507592585](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560507592585.png)

![1560507615771](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560507615771.png)

Everything is same as before except the parameters of `sym.check`.

```
;before    check(int passwork)
|   sym.check (int arg_8h);

;now       check(int password, char* argv[])
|   sym.check (int arg_8h, int arg_ch);
```

Then the environment pointer is passed to `sym.parell`

```
|   sym.parell (int arg_8h, int arg_ch);
```

There is a new function in `sym.parell`, named `sym.dummy`. Here are something interest:

```
|      ||   0x080484ee      c74424043887.  mov dword [local_4h_2], str.LOLO ; [0x8048738:4]=0x4f4c4f4c ; "LOLO" @ 0x8048738

|      ||   0x080484fc      e8d7feffff     call sym.imp.strncmp       ; int strncmp(const char *s1, const char *s2, size_t n)
```

Looks like the binary wants the same things as the previous one, plus an environment variable named `LOLO`.

![1560507715928](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560507715928.png)

## crackme0x07

![1560509713380](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560509713380.png)

The symbols seems have some error. `rabin2` with `-I`, we can see the binary info.

![1560509759047](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560509759047.png)

Noted that `stripped true`, so there have no more symbols.

```
[0x08048400]> pdf
            ;-- section..text:
/ (fcn) entry0 33
|   entry0 ();
|           0x08048400      31ed           xor ebp, ebp                ; section 13 va=0x08048400 pa=0x00000400 sz=900 vsz=900 rwx=--r-x .text
|           0x08048402      5e             pop esi
|           0x08048403      89e1           mov ecx, esp
|           0x08048405      83e4f0         and esp, 0xfffffff0
|           0x08048408      50             push eax
|           0x08048409      54             push esp
|           0x0804840a      52             push edx
|           0x0804840b      6850870408     push 0x8048750              ; "U......$........U..S.........................u.X[]..U..S."
|           0x08048410      68e0860408     push 0x80486e0
|           0x08048415      51             push ecx
|           0x08048416      56             push esi
|           0x08048417      687d860408     push main                   ; "U....." @ 0x804867d
\           0x0804841c      e867ffffff     call sym.imp.__libc_start_main; int __libc_start_main(func main, int argc, char **ubp_av, func init, func fini, func rtld_fini, void *stack_end)
```

Since this is GCC-produced code, the main is likely at `0x804867d` (the last push before `imp.__libc_start_main`)

```
[0x08048400]> pdf @ main
/ (fcn) main 99
|   main (int arg_10h);
|           ; var int local_78h @ ebp-0x78
|           ; arg int arg_10h @ ebp+0x10
|           ; var int local_4h @ esp+0x4
|              ; DATA XREF from 0x08048417 (entry0)
|           0x0804867d      55             push ebp
|           0x0804867e      89e5           mov ebp, esp
|           0x08048680      81ec88000000   sub esp, 0x88
|           0x08048686      83e4f0         and esp, 0xfffffff0
|           0x08048689      b800000000     mov eax, 0
|           0x0804868e      83c00f         add eax, 0xf
|           0x08048691      83c00f         add eax, 0xf
|           0x08048694      c1e804         shr eax, 4
|           0x08048697      c1e004         shl eax, 4
|           0x0804869a      29c4           sub esp, eax
|           0x0804869c      c70424d98704.  mov dword [esp], str.IOLI_Crackme_Level_0x07_n ; [0x80487d9:4]=0x494c4f49 ; "IOLI Crackme Level 0x07." @ 0x80487d9
|           0x080486a3      e810fdffff     call sym.imp.printf        ; int printf(const char *format)
|           0x080486a8      c70424f28704.  mov dword [esp], str.Password: ; [0x80487f2:4]=0x73736150 ; "Password: " @ 0x80487f2
|           0x080486af      e804fdffff     call sym.imp.printf        ; int printf(const char *format)
|           0x080486b4      8d4588         lea eax, dword [local_78h]
|           0x080486b7      89442404       mov dword [local_4h], eax
|           0x080486bb      c70424fd8704.  mov dword [esp], 0x80487fd  ; [0x80487fd:4]=0x7325 ; "%s"
|           0x080486c2      e8d1fcffff     call sym.imp.scanf         ; int scanf(const char *format)
|           0x080486c7      8b4510         mov eax, dword [arg_10h]    ; [0x10:4]=0x30002
|           0x080486ca      89442404       mov dword [local_4h], eax
|           0x080486ce      8d4588         lea eax, dword [local_78h]
|           0x080486d1      890424         mov dword [esp], eax
|           0x080486d4      e8e0feffff     call fcn.080485b9
|           0x080486d9      b800000000     mov eax, 0
|           0x080486de      c9             leave
\           0x080486df      c3             ret
[0x08048400]> pdf @ fcn.080485b9
/ (fcn) fcn.080485b9 196
|   fcn.080485b9 (int arg_8h, int arg_ch);
|           ; var int local_dh @ ebp-0xd
|           ; var int local_ch @ ebp-0xc
|           ; var int local_8h @ ebp-0x8
|           ; var int local_4h @ ebp-0x4
|           ; arg int arg_8h @ ebp+0x8
|           ; arg int arg_ch @ ebp+0xc
|           ; var int local_4h_2 @ esp+0x4
|           ; var int local_8h_2 @ esp+0x8
|              ; CALL XREF from 0x080486d4 (main)
|           0x080485b9      55             push ebp
|           0x080485ba      89e5           mov ebp, esp
|           0x080485bc      83ec28         sub esp, 0x28               ; '('
|           0x080485bf      c745f8000000.  mov dword [local_8h], 0
|           0x080485c6      c745f4000000.  mov dword [local_ch], 0
|              ; JMP XREF from 0x08048628 (fcn.080485b9)
|       .-> 0x080485cd      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0
|       |   0x080485d0      890424         mov dword [esp], eax
|       |   0x080485d3      e8d0fdffff     call sym.imp.strlen        ; size_t strlen(const char *s)
|       |   0x080485d8      3945f4         cmp dword [local_ch], eax   ; [0x13:4]=256
|      ,==< 0x080485db      734d           jae 0x804862a
|      ||   0x080485dd      8b45f4         mov eax, dword [local_ch]
|      ||   0x080485e0      034508         add eax, dword [arg_8h]
|      ||   0x080485e3      0fb600         movzx eax, byte [eax]
|      ||   0x080485e6      8845f3         mov byte [local_dh], al
|      ||   0x080485e9      8d45fc         lea eax, dword [local_4h]
|      ||   0x080485ec      89442408       mov dword [local_8h_2], eax
|      ||   0x080485f0      c7442404c287.  mov dword [local_4h_2], 0x80487c2 ; [0x80487c2:4]=0x50006425 ; "%d"
|      ||   0x080485f8      8d45f3         lea eax, dword [local_dh]
|      ||   0x080485fb      890424         mov dword [esp], eax
|      ||   0x080485fe      e8c5fdffff     call sym.imp.sscanf        ; int sscanf(const char *s,
|      ||   0x08048603      8b55fc         mov edx, dword [local_4h]
|      ||   0x08048606      8d45f8         lea eax, dword [local_8h]
|      ||   0x08048609      0110           add dword [eax], edx
|      ||   0x0804860b      837df810       cmp dword [local_8h], 0x10  ; [0x10:4]=0x30002
|     ,===< 0x0804860f      7512           jne 0x8048623
|     |||   0x08048611      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=0
|     |||   0x08048614      89442404       mov dword [local_4h_2], eax
|     |||   0x08048618      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0
|     |||   0x0804861b      890424         mov dword [esp], eax
|     |||   0x0804861e      e81fffffff     call 0x8048542
|     `---> 0x08048623      8d45f4         lea eax, dword [local_ch]
|      ||   0x08048626      ff00           inc dword [eax]
|      |`=< 0x08048628      eba3           jmp 0x80485cd
|      `--> 0x0804862a      e8f5feffff     call 0x8048524
|           0x0804862f      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=0
|           0x08048632      89442404       mov dword [local_4h_2], eax
|           0x08048636      8b45fc         mov eax, dword [local_4h]
|           0x08048639      890424         mov dword [esp], eax
|           0x0804863c      e873feffff     call 0x80484b4
|           0x08048641      85c0           test eax, eax
|       ,=< 0x08048643      7436           je 0x804867b
|       |   0x08048645      c745f4000000.  mov dword [local_ch], 0
|       |      ; JMP XREF from 0x08048679 (fcn.080485b9)
|      .--> 0x0804864c      837df409       cmp dword [local_ch], 9     ; [0x9:4]=0
|     ,===< 0x08048650      7f29           jg 0x804867b
|     |||   0x08048652      8b45fc         mov eax, dword [local_4h]
|     |||   0x08048655      83e001         and eax, 1
|     |||   0x08048658      85c0           test eax, eax
|    ,====< 0x0804865a      7518           jne 0x8048674
|    ||||   0x0804865c      c70424d38704.  mov dword [esp], str.wtf__n ; [0x80487d3:4]=0x3f667477 ; "wtf?." @ 0x80487d3
|    ||||   0x08048663      e850fdffff     call sym.imp.printf        ; int printf(const char *format)
|    ||||   0x08048668      c70424000000.  mov dword [esp], 0
|    ||||   0x0804866f      e874fdffff     call sym.imp.exit          ; void exit(int status)
|    `----> 0x08048674      8d45f4         lea eax, dword [local_ch]
|     |||   0x08048677      ff00           inc dword [eax]
|     |`==< 0x08048679      ebd1           jmp 0x804864c
|     `-`-> 0x0804867b      c9             leave
\           0x0804867c      c3             ret
```

The program logic is all the same.

```
s = 0
for i in password:
    s += i
    if s == 0x10:
        sym.parell()
print "Invalid"
```

In function `0x8048542`, there are something interest.

```
.--> 0x0804857f      837df809       cmp dword [ebp - 8], 9      ; [0x9:4]=0
,===< 0x08048583      7f32           jg 0x80485b7
```

So, `9` is the maximum length of password.

```
─birdpwn@ubuntu ~/Question/Re 
╰─$ LOLO= ./crackme0x07
IOLI Crackme Level 0x07
Password: 111111118
Password OK!
─birdpwn@ubuntu ~/Question/Re 
╰─$ LOLO= ./crackme0x07
IOLI Crackme Level 0x07
Password: 1111111117
Password Incorrect!
```

## Crackme0x08

![1560510229704](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510229704.png)

![1560510278208](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510278208.png)

![1560510327891](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510327891.png)

![1560510355951](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510355951.png)

It just like a unstripped version of crackme0x07.

![1560510422397](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510422397.png)

## crackme0x09

![1560510456266](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510456266.png)

It is stripped.

![1560510515137](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510515137.png)

![1560510567635](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510567635.png)

![1560510615679](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\1560510615679.png)

### 参考信息

https://firmianay.github.io/2017/02/20/ioli_crackme_writeup.html

