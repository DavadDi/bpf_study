#!/bin/bash
# mac sed -i "" 
# 发现 -i 需要带一个字符串，用来备份源文件
sed -i "" "s/https:\/\/www\.do1618\.com\/wp-content\/uploads\/2020\/08/imgs/g" README.md
