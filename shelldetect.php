<?php
/**
 * PHP Shell Detector v1.0
 * PHP Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>
 * https://github.com/emposha/PHP-Shell-Detector
 */

class shellDetector {
  private $extension = array('php');
  //settings: extensions that should be scanned
  private $showlinenumbers = true;
  //settings: show line number where suspicious function used
  private $dateformat = "H:i:s d/m/Y";
  //settings: used with access time & modified time
  private $langauge = '';
  //settings: if I want to use other language
  private $directory = '.';
  //settings: scan specific directory
  private $task = '';
  //settings: perform different task
  private $report_format = 'shelldetector_%h%i%d%m%Y.html';
  //settings: used with is_cron(true) file format for report file
  private $is_cron = false;
  //settings: if true run like a cron(no output)
  private $filelimit = 30000;
  //settings: maximum files to scan (more then 30000 you should scan specific directory)

  //system variables
  private $output = '';
  //system variable used with is_cron
  private $files = array();
  //system variable hold all scanned files
  private $badfiles = array();
  //system variable hold bad files
  private $fingerprints = array();
  //system: currently on dev
  private $title = 'PHP Shell Detector';
  //system: title

  /**
   * Constractor
   */
  function __construct($settings =null) {
    if(is_array($settings)) {
      $own = get_object_vars($this);
      foreach($settings as $key => $value) {
        if(key_exists($key, $own)) {
          $this->$key = $value;
        }
      }
    }
    if(file_exists('fingerprint.db')) {
      eval(base64_decode(file_get_contents('fingerprint.db')));
    }
  }

  /**
   * Start function
   */
  public function start() {
    $this->header();
    $this->version();
    switch ($this->task) {
      case 'getsha' :
        $this->filescan();
        $this->showsha();
        break;
      case 'update' :
        $this->update();
        break;
      default :
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
      //update mechanism
    }
  }
  
  /**
   * Check version function
   */
  private function version() {
    $version = isset($this->fingerprints['version']) ? $this->fingerprints['version'] : 0;
    $server_version = file_get_contents('http://www.websecure.co.il/phpshelldetector/api/?task=check&version=' . $version);
    if(strlen($server_version) != 0 && strcmp($server_version, $version) != 0) {
      $this->output($this->t('New version found. Please update!'));
      return true;
    } else if(strlen($server_version) == 0) {
      $this->output($this->t('Cant connect to server! New version check failed!'), 'error');
    }
    return false;
  }
  
  /**
   * Scan function executer
   */
  private function filescan() {
    $this->output($this->t('Starting file scanner, please be patient file scanning can take some time.'));
    $this->output('<div class="info">' . $this->t('Files found:') . '<span class="filesfound">', null, false);
    $this->listdir($this->directory);
    $this->output('</span></div>', null, false);
    if(count($this->files) > $this->filelimit) {
      $this->output($this->t('File limit reached, scanning process stopped.'));
    }
    $this->output($this->t('File scan done we have: @count files to analize', array("@count" => count($this->files))));
  }

  /**
   * Show sha1 for fond files
   */
  private function showsha() {
    foreach($this->files as $file) {
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
    foreach($this->files as $file) {
      if ($self == $file) {
        unset($file);
      }
      $extension = pathinfo($file);
      if(in_array($extension['extension'], $this->extension)) {
        $content = file_get_contents($file);
        if(preg_match_all('%(passthru|shell_exec|exec|base64_decode|eval|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source)%', $content, $matches)) {
          $this->output('<dl><dt>' . $this->t('Suspicious behavior found in:') . ' ' . basename($file) . '<span class="plus">-</span></dt>', null, false);
          $this->output('<dd><dl><dt>' . $this->t('Full path:') . '</dt><dd>' . $file . '</dd>', null, false);
          $this->output('<dt>' . $this->t('Owner:') . '</dt><dd>' . fileowner($file) . '</dd>', null, false);
          $this->output('<dt>' . $this->t('Permision:') . '</dt><dd>' . substr(sprintf('%o', fileperms($file)), -4) . '</dd>', null, false);
          $this->output('<dt>' . $this->t('Last accessed:') . '</dt><dd>' . date($this->dateformat, fileatime($file)) . '</dd>', null, false);
          $this->output('<dt>' . $this->t('Last modified:') . '</dt><dd>' . date($this->dateformat, filemtime($file)) . '</dd>', null, false);
          $this->output('<dt>' . $this->t('Filesize:') . '</dt><dd>' . $this->HumanReadableFilesize($file) . '</dd>', null, false);
          if($this->showlinenumbers) {
            $this->output('<dt>' . $this->t('suspicious functions used:') . '</dt><dd>', null, false);
            $_content = explode("\n", $content);
            for($line = 0; $line < count($_content); $line++) {
              if(preg_match_all('%(passthru|shell_exec|exec|base64_decode|eval|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source)%', $_content[$line], $matches)) {
                $lineid = md5($line . $file);
                $this->output($this->_implode($matches) . ' (<a href="#" class="showline" id="ne_' . $lineid . '">' . $this->t('line:') . $line . '</a>);', null, false);
                $this->output('<div class="hidden source" id="line_' . $lineid . '"><code>' . htmlentities($_content[$line]) . '</code></div>', null, false);
              }
            }
          } else {
            $this->output('<dt>' . $this->t('suspicious functions used:') . '</dt><dd>' . $this->_implode($matches) . '</dd>', null, false);
          }
          $counter++;
          $this->fingerprint($file, $content);
        }
      }
    }
    $this->output('', 'clearer');
    $this->output($this->t('@count suspicious files found and @shells shells found', array("@count" => $counter, "@shells" => count($this->badfiles) ? '<strong>'.count($this->badfiles).'</strong>' : count($this->badfiles))), (count($this->badfiles) ? 'error' : null));
  }

  /**
   * Fingerprint function
   */
  private function fingerprint($file, $content = null) {
    $key = 'Negative <small>(if wrong <a href="#" id="m_' . md5($file) . '" class="source_submit">submit file for analize</a>)</small><form id="form_' . md5($file) . '" action="http://www.websecure.co.il/phpshelldetector/api/?task=submit" method="post"><input type="hidden" name="code" value="' . base64_encode($content) . '" /></form>';
    $class = 'green';
    $base64_content = base64_encode($content);
    foreach ($this->fingerprints as $fingerprint => $shell) {
      if(preg_match("%$fingerprint%", $base64_content)) {
        $key = "Positive, it`s a " . $shell;
        $class = 'red';
        $this->badfiles[] = $file;
      }
    }
    $this->output('<dt>' . $this->t('Fingerprint:') . '</dt><dd class="' . $class . '">' . $key . '</dd></dl></dd></dl>', null, false);
  }

  /**
   * Recurcevly implode array
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
    $style = '<style type="text/css" media="all">body {background-color: #ccc;font: 13px tahoma, arial; color: #151515; direction: ltr;}h1{text-align:center;font-size:24px;}dl{margin:0px; padding:0px;}#content {width: 1024px;margin:0px auto;padding:35px 40px;border:1px solid #e8e8e8;background:#fff;overflow:hidden;-webkit-border-radius:7px;-moz-border-radius:7px;border-radius:7px;}dl dt{cursor: pointer;background:#5f9be3;color:#fff;float:left;font-weight:700;margin-right:10px;width:99%;position:relative;padding:5px}dl dt .plus{position:absolute;right:4px}dl dd{margin:2px 0;padding:5px 0}dl dd dl{margin-top:24px;margin-left:60px}dl dd dl dt{background:#4FCBA3!important;width:180px!important} .error{background-color: #FFEBE8;border: 1px solid #DD3C10;padding:4px 10px;margin: 5px 0px} .info{background-color:#fff9d7;border: 1px solid #e2c822;padding:4px 10px;margin: 5px 0px}.clearer{clear:both;height:0px;font-size:0px;}.hidden {display:none;}.green {font-weight: bold;color: #92B901;}.red {font-weight: bold;color: #DD3C10;}.green small {font-weight: normal !important;color: #151515 !important;}.filesfound {position: relative;}.files {position: absolute;background-color:#FFF9D7;left:4px;}</style>';
    $script = 'function init(){$("dt").click(function(){var text=$(this).children(".plus");if(text.length){$(this).next("dd").slideToggle();if(text.text()=="+"){text.text("-")}else{text.text("+")}}});$(".showline").click(function(){var id="li"+$(this).attr("id");$("#"+id).dialog({height:440,modal:true,width:600,title:"Source code"});return false});$(".source_submit").click(function(){var id="for"+$(this).attr("id");$("#"+id).submit();$(this).remove();return false})}$(document).ready(init);';
    $this->output('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><title>PHP Shell Detector</title>' . $style . '<link rel="stylesheet" href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/themes/base/jquery-ui.css" type="text/css" media="all" /><script src="http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js" type="text/javascript" charset="utf-8"></script><script src="https://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/jquery-ui.min.js" type="text/javascript" charset="utf-8"></script><script type="text/javascript">' . $script . '</script></head><body><h1>' . $this->title . '</h1><div id="content">', null, false);
  }

  /**
   * Output
   */
  private function output($content, $class ='info', $html =true) {
    if($this->is_cron) {
      if($html) {
        $this->output .= '<div class="' . $class . '">' . $content . '</div>';
      } else {
        $this->output .= $content;
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

  private function flush() {
    $filename = date($this->report_format, time());
    file_put_contents($filename, $this->output);
  }

  /**
   * Translate function (ported from Drupal)
   */
  private function t($string, $args = array()) {
    if($this->langauge) {
      if(is_file('lang/' . $this->langauge . '.php')) {
        include ('lang/' . $this->langauge . '.php');
        $string = $local[$string];
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
      return   strtr($string, $args);
    }
  }

  /**
   * Recursivly list directories
   */
  private function listdir($dir) {
    $handle = opendir($dir);
    if(count($this->files) > $this->filelimit) {
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
        $this->files[] = $filepath;
      } else if(is_dir($filepath)) {
        $this->listdir($filepath);
      }
    }
    $this->output('<span class="files">' . count($this->files) . '</span>', null, false);
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

//own error handler
set_error_handler( array("shellDetector", "error_handler"));
$shelldetector = new shellDetector(array('extension' => array('php', 'txt')));
$shelldetector->start();
?>
