python-debugger-api-
====================

linux debugger api  wriiten by python

只需mydebug.py 和 ptrace_arg.py 即可
其他檔案只是範例

能改進的地方很多，只花一個多禮拜生出來的code就不要計較了

設計的原則是提供python寫的api
接著我們就可以利用這些api的組合來解決問題


使用說明：
./injectso.py [pid] ./hitcon.so

./hook.py [pid]

即可攔截目標function

技術手冊：
hitcon 2014 agenda 有pdf可下載

