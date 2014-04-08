Web Shell Detector
==================
<img src="http://www.emposha.com/wp-content/uploads/2011/07/shelldetect3-300x201.png" width="100" align="left" style="padding-right: 4px;" /> Web Shell Detector – is a php script that helps you find and identify php/cgi(perl)/asp/aspx shells. Web Shell Detector has a “web shells” signature database that helps to identify “web shell” up to 99%. By using the latest javascript and css technologies, web shell detector has a light weight and friendly interface.

Web Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>

Console version (python): https://github.com/emposha/Shell-Detector


Contributors
------------
Piotr Łuczko

John Thornton

Detection
---------

  Number of known shells: 551

Requirements
------------
PHP 5.x, OpenSSL (only for secure file submission)

Usage
-----
To activate Web Shell Detector:

1) Upload shelldetect.php and shelldetect.db to your root directory

2) Open shelldetect.php file in your browser

    Example: http://www.website.com/shelldetect.php

3) Inspect all strange files, if some of files look suspicious, send them to http://www.shelldetector.com team. After submitting your file, it will be inspected and if there are any threats, it will be inserted into a “web shell detector” web shells signature database.

4) If any web shells found and identified use your ftp/ssh client to remove it from your web server (IMPORTANT: please be carefull because some of shells may be integrated into system files!).

Demo
----

    http://www.emposha.com/demo/shelldetect/

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

 - 1.66 thanks to John Thornton for small tweeks and php 5.3.3 support
 
 - 1.64 settings ini file support added(in case that you want to use same settings without code changing), output method rewriten, is_cron fixed, italian translation added (thanks to Marco Saiu)
 
 - 1.63 new shell recognize mechanizm added, shell signatures updated.
 
 - 1.62 version of jquery reverted to 1.7.x due bug with jquery ui dialog, new type of files added, shells signatures updated
 
 - 1.61 added new way to send suspicious files, some css & code fixes, new shells signatures added
 
 - 1.6 added support to indicate not shell files (but still those files need  to be removed), loader indicator added
 
 - 1.52 noindex meta tag added (to remove script from search results), scann all files options added: extension = *

 - 1.51 unpack function update
 
 - 1.5 unpack function added, application version check added, many warnings fixed, error handler fixed.
 
 - 1.4 hide suspicious files option added, file scanning changed.

 - 1.3 submission of suspicious file to shelldetector.com changed, email field added with ability to get notify about suspicious file.
 
 - 1.2 encryption function added, authentication added, some small bugs fixed

 - 1.1 fingerprint function change
       show line regex changed

 - 1.0 first version