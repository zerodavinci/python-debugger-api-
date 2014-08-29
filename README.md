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

即可攔截目標function，因為用到ptrace的attach
所以hook.py和injectso.py需要root權限
injectso.py有時會失敗,可以多試幾次

injectso的功能在glibc 2.17~2.19測試過正常運作
2.15則會有問題，有時會造成目標crash,
2.16則沒測過不知道會不會有問題

技術手冊：
hitcon 2014 agenda 有pdf可下載
