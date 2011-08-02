<?php
/**
 * PHP Shell Detector v1.2
 * PHP Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>
 * https://github.com/emposha/PHP-Shell-Detector
 */

//no timeout
set_time_limit(0);

//own error handler
set_error_handler( array("shellDetector", "error_handler"));
$shelldetector = new shellDetector(array('extension' => array('php', 'txt')));
$shelldetector->start();

class shellDetector {
  private $extension = array('php'); //settings: extensions that should be scanned
  private $showlinenumbers = true; //settings: show line number where suspicious function used
  private $dateformat = "H:i:s d/m/Y"; //settings: used with access time & modified time
  private $langauge = ''; //settings: if I want to use other language
  private $directory = '.'; //settings: scan specific directory
  private $scan_hidden = true; //settings: scan hidden files & directories
  private $task = ''; //settings: perform different task
  private $report_format = 'shelldetector_%h%i%d%m%Y.html'; //settings: used with is_cron(true) file format for report file
  private $is_cron = false; //settings: if true run like a cron(no output)
  private $filelimit = 30000; //settings: maximum files to scan (more then 30000 you should scan specific directory)
  private $useget = false; //settings: activate task by get
  private $authentication = array("username" => "admin", "password" => "protect"); //settings: protect script with user & password in case to disable simply set to NULL
  private $remotefingerprint = false; //settings: get shells signatures db by remote
  
  //system variables
  private $_output = ''; //system variable used with is_cron
  private $_files = array(); //system variable hold all scanned files
  private $_badfiles = array(); //system variable hold bad files
  private $fingerprints = array(); //system: hold shells singnatures
  private $_title = 'PHP Shell Detector'; //system: title
  private $_version = '1.2'; //system: version of shell detector
  private $_regex = '%(\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)%'; //system: regex for detect Suspicious behavior
  private $_public_key = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JR2ZNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRRDZCNWZaY2NRN2dROS93TitsWWdONUViVU4NClNwK0ZaWjcyR0QvemFrNEtDWkZISEwzOHBYaS96bVFBU1hNNHZEQXJjYllTMUpodERSeTFGVGhNb2dOdzVKck8NClA1VGprL2xDcklJUzVONWVhYUQvK1NLRnFYWXJ4bWpMVVhmb3JIZ25rYUIxQzh4dFdHQXJZWWZWN2lCVm1mRGMNCnJXY3hnbGNXQzEwU241ZDRhd0lEQVFBQg0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tDQo='; //system: public key to encrypt file content

  /**
   * Constructor
   */
  function __construct($settings =null) {
    if(is_array($settings)) {
      $own = get_object_vars($this);
      foreach($settings as $key => $value) {
        if(key_exists($key, $own) && substr($key,0, 1) != '_') {
          $this->$key = $value;
        }
      }
    }
    
    if ($this->authentication != null) {
      if ((!isset($_SERVER['PHP_AUTH_USER']) || (isset($_SERVER['PHP_AUTH_USER']) && $_SERVER['PHP_AUTH_USER'] != $this->authentication['username'])) && (!isset($_SERVER['PHP_AUTH_PW']) ||(isset($_SERVER['PHP_AUTH_PW']) && $_SERVER['PHP_AUTH_PW'] != $this->authentication['password']))) {
        header('WWW-Authenticate: Basic realm="Login"');
        header('HTTP/1.0 401 Unauthorized');
        echo 'Please login to continue.';
        exit;
      }
    }
    
    if ($this->useget && isset($_GET['task'])) {
      $this->task = $_GET['task'];
    }
    
    if(file_exists('shelldetect.db')) {
      $this->fingerprints = unserialize(base64_decode(file_get_contents('shelldetect.db')));
    }

    if ($this->remotefingerprint) {
      $this->fingerprints = unserialize(base64_decode(file_get_contents('http://www.websecure.co.il/phpshelldetector/api/?task=getlatest')));
    }
  }

  /**
   * Start function
   */
  public function start() {
    $this->header();
    if (!function_exists('openssl_public_encrypt')) {
      $this->output($this->t('Please note <strong>openssl</strong> library not found, suspicious files will be included in html without encryption.'), 'error');
    }
    if (count($this->fingerprints) == 0) {
      $this->output($this->t('Please note, shells signature database not found, suspicious files will be scan only by behavior.'), 'error');
    }
    switch ($this->task) {
      case 'getsha' :
        $this->filescan();
        $this->showsha();
        break;
      case 'update' :
        $this->update();
        break;
      default :
        $this->version();
        $this->filescan();
        $this->anaylize();
        break;
    }
    $this->footer();
    if($this->is_cron) {
      $this->flush();
    }
  }
  
  /**
   * Update function get lates update
   */
  private function update() {
    if($this->version()) {
      $content = file_get_contents('http://www.websecure.co.il/phpshelldetector/api/?task=getlatest');
      chmod('shelldetect.db', 0777);
      if (file_put_contents('shelldetect.db', $content)) {
        $this->output($this->t('Shells signature database updated succesfully!'));
      }
      else {
        $this->output($this->t('Cant save shells signature database please check permissions'), 'error');
      }
    }
    else {
      $this->output($this->t('Your shells signatures database already updated!'));
    }
  }
  
  /**
   * Check version function
   */
  private function version() {
    $version = isset($this->fingerprints['version']) ? $this->fingerprints['version'] : 0;
    $server_version = file_get_contents('http://www.websecure.co.il/phpshelldetector/api/?task=checkver');
    if(strlen($server_version) != 0 && intval($server_version) != 0 && (intval($server_version) >  intval($version))) {
      $this->output($this->t('New version of shells signature database found. Please update!'), 'error');
      return true;
    } else if(strlen($server_version) == 0 || intval($server_version) == 0) {
      $this->output($this->t('Cant connect to server! Version check failed!'), 'error');
    }
    return false;
  }
  
  /**
   * Scan function executer
   */
  private function filescan() {
    $this->output($this->t('Starting file scanner, please be patient file scanning can take some time.'));
    $this->output($this->t('Number of known shells in database is: '). (count($this->fingerprints)));
    $this->output('<div class="info">' . $this->t('Files found:') . '<span class="filesfound">', null, false);
    $this->listdir($this->directory);
    $this->output('</span></div>', null, false);
    if(count($this->_files) > $this->filelimit) {
      $this->output($this->t('File limit reached, scanning process stopped.'));
    }
    $this->output($this->t('File scan done, we have: @count files to analize', array("@count" => count($this->_files))));
  }

  /**
   * Show sha1 for found files
   */
  private function showsha() {
    foreach($this->_files as $file) {
      $this->output('<dl><dt>' . $this->t('Show sha for file:') . ' ' . basename($file) . '<span class="plus">-</span></dt>', null, false);
      $this->output('<dd><dl><dt>' . $this->t('Full path:') . '</dt><dd>' . $file . '</dd>', null, false);
      $this->output('<dt>' . $this->t('Sha1:') . '</dt><dd>' . sha1_file($file) . '</dd></dl></dd></dl>', null, false);
    }
    $this->output('', 'clearer');
  }

  /**
   * Check files for using suspicious function
   */
  private function anaylize() {
    $counter = 0;
    $self = basename(__FILE__);
    foreach($this->_files as $file) {
      if ($self == $file) {
        unset($file);
      }
      $extension = pathinfo($file);
      if(in_array($extension['extension'], $this->extension)) {
        $flag = false;
        $content = file_get_contents($file);
        if(preg_match_all($this->_regex, $content, $matches)) {
          $flag = true;
          $this->fileInfo($file);
          if($this->showlinenumbers) {
            $this->output('<dt>' . $this->t('suspicious functions used:') . '</dt><dd>', null, false);
            $_content = explode("\n", $content);
            for($line = 0; $line < count($_content); $line++) {
              if(preg_match_all($this->_regex, $_content[$line], $matches)) {
                $lineid = md5($line . $file);
                $this->output($this->_implode($matches) . ' (<a href="#" class="showline" id="ne_' . $lineid . '">' . $this->t('line:') . ($line + 1) . '</a>);', null, false);
                $this->output('<div class="hidden source" id="line_' . $lineid . '"><code>' . htmlentities($_content[$line]) . '</code></div>', null, false);
              }
            }
            $this->output('&nbsp;</dd>', null, false);
          } else {
            $this->output('<dt>' . $this->t('suspicious functions used:') . '</dt><dd>' . $this->_implode($matches) . '&nbsp;</dd>', null, false);
          }
          $counter++;
        }
        $this->fingerprint($file, $content, $flag);
      }
    }
    $this->output('', 'clearer');
    $this->output($this->t('<strong>Status</strong>: @count suspicious files found and @shells shells found', array("@count" => $counter, "@shells" => count($this->_badfiles) ? '<strong>'.count($this->_badfiles).'</strong>' : count($this->badfiles))), (count($this->_badfiles) ? 'error' : 'success'));
  }

  private function fileInfo($file) {
    $this->output('<dl><dt>' . $this->t('Suspicious behavior found in:') . ' ' . basename($file) . '<span class="plus">-</span></dt>', null, false);
    $this->output('<dd><dl><dt>' . $this->t('Full path:') . '</dt><dd>' . $file . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Owner:') . '</dt><dd>' . fileowner($file) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Permission:') . '</dt><dd>' . substr(sprintf('%o', fileperms($file)), -4) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Last accessed:') . '</dt><dd>' . date($this->dateformat, fileatime($file)) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Last modified:') . '</dt><dd>' . date($this->dateformat, filemtime($file)) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Filesize:') . '</dt><dd>' . $this->HumanReadableFilesize($file) . '</dd>', null, false);
  }

  /**
   * Fingerprint function
   */
  private function fingerprint($file, $content = null, $flag = false) {
    $key = $this->t('Negative').' <small class="source_submit_parent">('.$this->t('if wrong').' <a href="#" id="m_' . md5($file) . '" class="source_submit">'.$this->t('submit file for analize').'</a>)</small>';
    $key .= '<iframe border="0" scrolling="no" class="hidden" id="iform_' . md5($file) . '" name="iform_' . md5($file) . '" src="http://www.websecure.co.il/phpshelldetector/api/loader.html" />"></iframe>';
    $key .= '<form id="form_' . md5($file) . '" target="iform_' . md5($file) . '" action="http://www.websecure.co.il/phpshelldetector/api/?task=submit" method="post">';
    if (function_exists('openssl_public_encrypt')) {
      if (openssl_public_encrypt(base64_encode($content), $crypted_data, base64_decode($this->_public_key))) {
        $key .= '<input type="hidden" name="crypted" value="1" /><input type="hidden" name="code" value="' . base64_encode($crypted_data) . '" /></form>';
      } else {
        $key .= '<input type="hidden" name="code" value="' . base64_encode($content) . '" /></form>';
      }
    } else {
      $key .= '<input type="hidden" name="code" value="' . base64_encode($content) . '" /></form>';
    }
    $class = 'green';
    $base64_content = base64_encode($content);
    foreach ($this->fingerprints as $fingerprint => $shell) {
      if(preg_match("/".preg_quote($fingerprint, '/')."/", $base64_content)) {
        $key = $this->t('Positive, it`s a ') . $shell;
        $class = 'red';
        $this->_badfiles[] = $file;
        break;
      }
    }
    if ($flag) {
      $this->output('<dt>' . $this->t('Fingerprint:') . '</dt><dd class="' . $class . '">' . $key . '</dd></dl></dd></dl>', null, false);
    } else if ($class == 'red') {
      $this->fileInfo($file);
      $this->output('<dt>' . $this->t('Fingerprint:') . '</dt><dd class="' . $class . '">' . $key . '</dd></dl></dd></dl>', null, false);
    }
  }

  /**
   * Recursively implode array
   */
  private function _implode($array, $glue =', ') {
    $temp = array();
    foreach($array as $value) {
      if(is_array($value)) {
        $temp[] = $this->_implode($value);
      } else {
        $temp[] = $value;
      }
    }
    return   implode($glue, array_unique($temp));
  }

  /**
   * Output footer function
   */
  private function footer() {
    $this->output('</div></body></html>', null, false);
  }

  /**
   * Output header function
   */
  private function header() {
    $style = '<style type="text/css" media="all">body{background-color:#ccc;font:13px tahoma,arial;color:#151515;direction:ltr}h1{text-align:center;font-size:24px}dl{margin:0;padding:0}#content{width:1024px;margin:0 auto;padding:35px 40px;border:1px solid #e8e8e8;background:#fff;overflow:hidden;-webkit-border-radius:7px;-moz-border-radius:7px;border-radius:7px}dl dt{cursor:pointer;background:#5f9be3;color:#fff;float:left;font-weight:700;margin-right:10px;width:99%;position:relative;padding:5px}dl dt .plus{position:absolute;right:4px}dl dd{margin:2px 0;padding:5px 0}dl dd dl{margin-top:24px;margin-left:60px}dl dd dl dt{background:#4fcba3!important;width:180px!important}.error{background-color:#ffebe8;border:1px solid #dd3c10;padding:4px 10px;margin:5px 0}.success{background-color:#fff;border:1px solid #bdc7d8;padding:4px 10px;margin:5px 0}.info{background-color:#fff9d7;border:1px solid #e2c822;padding:4px 10px;margin:5px 0}.clearer{clear:both;height:0;font-size:0}.hidden{display:none}.green{font-weight:700;color:#92b901}.red{font-weight:700;color:#dd3c10}.green small{font-weight:400!important;color:#151515!important}.filesfound{position:relative}.files{position:absolute;left:4px;background-color:#fff9d7}iframe{border:0px;height:14px}</style>';
    $script = 'function init(){$("dt").click(function(){var text=$(this).children(".plus");if(text.length){$(this).next("dd").slideToggle();if(text.text()=="+"){text.text("-")}else{text.text("+")}}});$(".showline").click(function(){var id="li"+$(this).attr("id");$("#"+id).dialog({height:440,modal:true,width:600,title:"Source code"});return false});$(".source_submit").click(function(){var id="for"+$(this).attr("id");$("#"+id).submit();$(this).parent().remove();console.log(id);$("#i"+id).removeClass("hidden");return false})}$(document).ready(init);';
    $this->output('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><title>PHP Shell Detector</title>' . $style . '<link rel="stylesheet" href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/themes/base/jquery-ui.css" type="text/css" media="all" /><script src="http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js" type="text/javascript" charset="utf-8"></script><script src="https://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/jquery-ui.min.js" type="text/javascript" charset="utf-8"></script><script type="text/javascript">' . $script . '</script></head><body><h1>' . $this->_title . '</h1><div id="content">', null, false);
  }

  /**
   * Output
   */
  private function output($content, $class ='info', $html =true) {
    if($this->is_cron) {
      if($html) {
        $this->_output .= '<div class="' . $class . '">' . $content . '</div>';
      } else {
        $this->_output .= $content;
      }
    } else {
      if($html) {
        print '<div class="' . $class . '">' . $content . '</div>';
      } else {
        print $content;
      }
      flush();
    }
  }

  /**
   * Save scanned data to file
   */
  private function flush() {
    $filename = date($this->report_format, time());
    file_put_contents($filename, $this->_output);
  }

  /**
   * Translate function (ported from Drupal)
   */
  private function t($string, $args = array()) {
    if($this->langauge) {
      if(is_file('lang/' . $this->langauge . '.php')) {
        include ('lang/' . $this->langauge . '.php');
        if (isset($local[$string])) {
          $string = $local[$string];
        }
      }
    }

    if(empty($args)) {
      return $string;
    } else {
      foreach($args as $key => $value) {
        switch ($key[0]) {
          case '@' :
            $args[$key] = $value;
            break;
        }
      }
      return strtr($string, $args);
    }
  }

  /**
   * Recursivly list directories
   */
  private function listdir($dir) {
    $handle = opendir($dir);
    if(count($this->_files) > $this->filelimit) {
      return true;
    }
    while(($file = readdir($handle)) !== false) {
      if($file == '.' || $file == '..') {
        continue ;
      }
      $filepath = $dir == '.' ? $file : $dir . '/' . $file;
      if(is_link($filepath)) {
        continue ;
      }
      if(is_file($filepath)) {
        if(substr(basename($filepath), 0, 1) != "." || $this->scan_hidden) {
          $this->_files[] = $filepath;
        }
      } else if(is_dir($filepath)) {
        if(substr(basename($filepath), 0, 1) != "." || $this->scan_hidden) {
          $this->listdir($filepath);
        }
      }
    }
    $this->output('<span class="files">' . count($this->_files) . '</span>', null, false);
    closedir($handle);
  }

  /**
   * Returns a human readable filesize
   * @author      wesman20 (php.net)
   * @author      Jonas John
   * @version     0.3
   * @link        http://www.jonasjohn.de/snippets/php/readable-filesize.htm
   */
  private function HumanReadableFilesize($file) {
    $size = filesize($file);
    $mod = 1024;
    $units = explode(' ', 'B KB MB GB TB PB');
    for($i = 0; $size > $mod; $i++) {
      $size /= $mod;
    }
    return round($size, 2) . ' ' . $units[$i];
  }

  /**
   * Own error handler
   */
  public function error_handler($errno, $errstr, $errfile, $errline) {
    switch ($errno) {
      case E_USER_ERROR :

      case E_USER_NOTICE :
        $this->output('<strong>' . $this->t('Error: ') . '</strong>' . $errstr, 'error');
        break;
    }
  }

}
?>