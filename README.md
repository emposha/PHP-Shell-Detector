PHP Shell Detector
==================
PHP Shell Detector - is php script that help to find and identify php shells. With a database of known shells all process of shell scanning is very easy. PHP Shell Detector have very friendly interface. 

PHP Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>

PHP Shell Detector sponsored by http://www.websecure.co.il

Requirements
------------
PHP 5.x, OpenSSL

Usage
-----
To activate PHP Shell Detector:

1) Upload to your root directory

2) Open this file in your browser

    Example: http://www.website.com/shelldetect.php

3) Inspect all strange files, if some of files look suspicious, send them to us. If this file is a shell we will insert this file to our fingerprint database

4) If shells found and identified remove it (please be carefull because some of shells may be integrated into system files!).

Options
-------
 - extension - extensions that should be scanned
 - showlinenumbers - show line number where suspicious function used
 - dateformat - used with access time & modified time
 - langauge - if I want to use other language
 - directory - scan specific directory
 - task - perform different task
 - report_format - used with is_cron(true) file format for report file
 - is_cron - if true run like a cron(no output)
 - filelimit - maximum files to scan (more then 30000 you should scan specific directory)
 - useget - activate _GET variable for easy way to recive tasks
 - authentication  - protect script with user & password in case to disable simply set to NULL
 - remotefingerprint - get shells signatures db by remote
  

Changelog
---------
 - 1.2 encryption function added, authentication added, some small bugs fixed

 - 1.1 fingerprint function change
       show line regex changed

 - 1.0 first version