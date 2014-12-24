tcp_v895
========
Bee Beans 社製 VME Master で CAEN V895 16CH VME Discriminator を設定するプログラム。
TCP通信でVME　bus へアクセスできる。


ToDo
===
１、VME Master側の仕様なのか、クライアント側（本プログラム側）で正しくsocket をclose しないとモジュールがハングして応答しなくなる。
なので、socket 部分をclass化して、デストラクタ部分でclose させれば大丈夫か？
=> ダメ、try catch で例外処理でsocket close させましょう (exit はmain関数内で定義したlocal変数のデストラクタは呼んでくれない)
