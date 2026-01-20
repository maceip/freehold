```
                         QQYSUSU          UQOQQQQUWY
                    USYSQSQWUY SUSSSW   SOS       QS
                 WSSY                WQQQ    QY     SW
 YUQQUYWUQQQSUSQW                          YS  USW   Q
           YQS                                    Y  UY
U     QUY                                        S
     US  QY                                      W  UY
   WU     Y                                       SQW
                                                   YSY
    YU  U                               WSQY         QY
U                     SQW                             U
 SQW                                                  YS
  SSW                                                  WU
  QY                                     YWY            Y
  QY                                    WUS QU          WU
  SY                  WUQYUY            U SOQ      Y     UU
  SW                  YUSQQQ   UY  Y  YYU     YY          YSSU
  WW                   W    UW           U  U                UU
  UW           YUUUWWYWWW  W     SOSOOS    U                 WS
 WQ                       S      UOQOQ      W                 WQ
SQW                       Y        YU                          SW
QW                                                             WW
SY                                           QW                UY
OY                        Q                 Y                 YS
Q                       YUYW                U                 SW
Q                           U              W                 WS
QY                           WY          W                  WQ
SSY                             YWYWWUW                    US
 WUY                               YQS                   YQU
   UW                               WSY                YQS
    US      YYY                                     YSQQQS
      QSSQUWYYYWSQU                   Y             Y    WQSW
U  SQQ            YS               YQWW UUWWSW              WQS
QOUY                          WSU                USW          YSU
Y                         YSW                        YW  WS     YSY
                        SU                Y             U  QW     SW
                     YS                  YWWWWW   Y       Y  QY    WSY
                     SY                Y    Y    Y         UY YU     USW
            WS     UY               Y   UWW         WWW      S U       WQS
          UQY     S               WWWWW UWW    Y     Y        SYQYUY     U
           WU    Q            WY  WWWWW YWY   Y                U S       W
            YQ  U             Y     YWWU Y                      QYQ
             YQU                                  WWWW           WWW
```

<h3 align="center">carebears</h3>
<p align="center">sharing is caring</p>

---

carebears makes your local server reachable from the internet. run something on localhost, get a public https url.

no port forwarding. no dynamic dns. traffic flows through relays you control, not someone elses servers.

### install

```
cargo install --path .
```

### usage

```
carebears run --domain myapp.example.com --target 127.0.0.1:8080
```

### tray icon

run with `--tray` to get a bear in your system tray. happy bear means working. grumpy bear means broken. sleepy bear means starting. bedtime bear means stopping.

needs gtk on linux: `sudo apt install libgtk-3-dev libappindicator3-dev`

### license

mit
