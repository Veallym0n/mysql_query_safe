mysql_query_safe
================

safety php mysql_query function

简单的来说，就是封装一次mysql_query，在之前先用PHP_MYSQL_PARSER先验证一次，把危险的函数和明显是SQL注入使用的一些语句给特么的差出来然后fuckoff了就不干啥了。
