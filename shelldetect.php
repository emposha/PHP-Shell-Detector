<?php
/**
 * PHP Shell Detector v1.0
 * PHP Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>
 * https://github.com/emposha/PHP-Shell-Detector
 */

class shellDetector {
  private $files = array();
  private $extension = '.php';
  private $badfiles = array();
  private $title = 'PHP Shell Detector';
  private $showlinenumbers = false;
  private $dateformat = "H:i:s d/m/Y";
  private $langauge = '';
  private $fingerprints = array('7b592b9bb69424fa2a38704915a56b4050662c4d' => 'c99 (compressed)');
  private $task = '';
  /**
   * Constractor
   */
  function __construct($settings = null) {
    if (is_array($settings)) {
      $own = get_object_vars($this);
      foreach ($settings as $key => $value) {
        if (key_exists($key, $own)) {
          $this->$key = $value;
        }
      }
    }
  }
  
  /**
   * Start function
   */
  public function start() {
    $this->header();
    $this->output($this->t('Starting file scanner'));
    $this->listdir('.');
    $this->output($this->t('File scan done we have: @count files to analize', array("@count" => count($this->files))));
    switch ($this->task) {
      case 'getsha':
        $this->showsha();
        break;
      default:
        $this->anaylize();
        break;
    }
    $this->footer();
  }
  
  function showsha() {
    foreach ($this->files as $file) {
      $this->output('<dl><dt>'.$this->t('Show sha for file:').' '.basename($file).'<span class="plus">-</span></dt>', null, false);
      $this->output('<dd><dl><dt>'.$this->t('Full path:').'</dt><dd>'.$file.'</dd>', null, false);
      $this->output('<dt>'.$this->t('Sha1:').'</dt><dd>'.sha1_file ($file).'</dd></dl></dd></dl>', null, false);
    }
    $this->output('', 'clearer');
  }
  
  /**
   * Check files for using suspicious function
   */
  private function anaylize() {
    foreach ($this->files as $file) {
      if (preg_match('#'.addslashes($this->extension).'#', $file)) {
        $content = file_get_contents($file);
        if ($this->showlinenumbers) {
          $flag = false;
          $output = '<dl><dt>'.$this->t('Suspicious behavior found in:').' '.basename($file).'<span class="plus">-</span></dt>';
          $output .= '<dd><dl><dt>'.$this->t('Full path:').'</dt><dd>'.$file.' <small>(<a href="#">'.$this->t('show source').'</a>)</small></dd>';
          $output .= '<dt>'.$this->t('Owner:').'</dt><dd>'.fileowner($file).'</dd>';
          $output .= '<dt>'.$this->t('Permision:').'</dt><dd>'.substr(sprintf('%o', fileperms($file)), -4).'</dd>';
          $output .= '<dt>'.$this->t('Last accessed:').'</dt><dd>'.date($this->dateformat, fileatime($file)).'</dd>';
          $output .= '<dt>'.$this->t('Last modified:').'</dt><dd>'.date($this->dateformat, filemtime($file)).'</dd>';
          $output .= '<dt>'.$this->t('Filesize:').'</dt><dd>'.$this->HumanReadableFilesize($file).'</dd>';
          $output .= '<dt>'.$this->t('suspicious functions used:').'</dt><dd>';
          $content = explode("\n", $content);
          for ($line = 0; $line < count($content); $line++) {
            if (preg_match_all('%(passthru|shell_exec|exec|base64_decode|eval|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source)%', $content[$line], $matches)) {
              $flag = true;
              $lineid = md5($line.$file);
              $output .= $this->_implode($matches).' (<a href="#" class="showline" id="ne_'.$lineid.'">'.$this->t('line:').$line.'</a>);';
              $output .= '<div class="hidden source" id="line_'.$lineid.'"><code>'.$content[$line].'</code></div>';
            }
          }
          if ($flag) {
            $key = "Negative";
            $sha1 = sha1_file($file);
            if (key_exists($sha1, $this->fingerprints)) {
              $key = "Positive, it`s a " . $this->fingerprints[$sha1];
            }
            $output .= '<dt>'.$this->t('Fingerprint:').'</dt><dd class="'.($key == 'Negative' ? 'green' : 'red').'">'.$key.'</dd>';
            $this->output($output.'</dd></dl></dd></dl>', null, false);
            $this->badfiles[] = $file;
          }
        }
        else {
          if (preg_match_all('%(passthru|shell_exec|exec|base64_decode|eval|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source)%', $content, $matches)) {
            $this->output('<dl><dt>'.$this->t('Suspicious behavior found in:').' '.basename($file).'<span class="plus">-</span></dt>', null, false);
            $this->output('<dd><dl><dt>'.$this->t('Full path:').'</dt><dd>'.$file.'</dd>', null, false);
            $this->output('<dt>'.$this->t('Owner:').'</dt><dd>'.fileowner($file).'</dd>', null, false);
            $this->output('<dt>'.$this->t('Permision:').'</dt><dd>'.substr(sprintf('%o', fileperms($file)), -4).'</dd>', null, false);
            $this->output('<dt>'.$this->t('Last accessed:').'</dt><dd>'.date($this->dateformat, fileatime($file)).'</dd>', null, false);
            $this->output('<dt>'.$this->t('Last modified:').'</dt><dd>'.date($this->dateformat, filemtime($file)).'</dd>', null, false);
            $this->output('<dt>'.$this->t('Filesize:').'</dt><dd>'.$this->HumanReadableFilesize($file).'</dd>', null, false);
            $this->output('<dt>'.$this->t('suspicious functions used:').'</dt><dd>'.$this->_implode($matches).'</dd>', null, false);
            $key = "Negative";
            $sha1 = sha1_file($file);
            if (key_exists($sha1, $this->fingerprints)) {
              $key = "Positive, it`s a " . $this->fingerprints[$sha1];
            }
            $this->output('<dt>'.$this->t('Fingerprint:').'</dt><dd class="'.($key == 'Negative' ? 'green' : 'red').'">'.$key.'</dd></dl></dd></dl>', null, false);
            $this->badfiles[] = $file;
          }
        }
      }
    }
    $this->output('', 'clearer');
    $this->output($this->t('Suspicious @count files found. From them we found @shells shells', array("@count" => count($this->badfiles))), (count($this->badfiles) ? 'error' : null));
  }
  
  /**
   * Recurcevly implode array
   */
  private function _implode($array, $glue = ', ') {
    $temp = array();
    foreach ($array as $value) {
      if (is_array($value)) {
        $temp[] = $this->_implode($value);
      }
      else {
        $temp[] = $value;
      }
    }
    return implode($glue, array_unique($temp));
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
    $style = '<style type="text/css" media="all">body {background-color: #ccc;font: 13px tahoma, arial; color: #151515; direction: ltr;}h1{text-align:center;font-size:24px;}dl{margin:0px; padding:0px;}#content {width: 1024px;margin:0px auto;padding:35px 40px;border:1px solid #e8e8e8;background:#fff;overflow:hidden;-webkit-border-radius:7px;-moz-border-radius:7px;border-radius:7px;}dl dt{cursor: pointer;background:#5f9be3;color:#fff;float:left;font-weight:700;margin-right:10px;width:99%;position:relative;padding:5px}dl dt .plus{position:absolute;right:4px}dl dd{margin:2px 0;padding:5px 0}dl dd dl{margin-top:24px;margin-left:60px}dl dd dl dt{background:#4FCBA3!important;width:180px!important} .error{background-color: #FFEBE8;border: 1px solid #DD3C10;padding:4px 10px;margin: 5px 0px} .info{background-color:#fff9d7;border: 1px solid #e2c822;padding:4px 10px;margin: 5px 0px}.clearer{clear:both;height:0px;font-size:0px;}.hidden {display:none;}.green {font-weight: bold;color: #92B901;}.red {font-weight: bold;color: #DD3C10;}</style>';
    $script = 'function init(){$("dt").click(function(){var text=$(this).children(".plus");if(text.length){$(this).next("dd").slideToggle();if(text.text()=="+"){text.text("-")}else{text.text("+")}}});$(".showline").click(function(){var id="li"+$(this).attr("id");$("#"+id).dialog({height:440,modal:true,width:600,title:"Source code"});return false;})}$(document).ready(init);';
    $this->output('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><title>PHP Shell Detector</title>'.$style.'<link rel="stylesheet" href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/themes/base/jquery-ui.css" type="text/css" media="all" /><script src="http://ajax.aspnetcdn.com/ajax/jQuery/jquery-1.6.min.js" type="text/javascript" charset="utf-8"></script><script src="https://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/jquery-ui.min.js" type="text/javascript" charset="utf-8"></script><script type="text/javascript">'.$script.'</script></head><body><h1>'.$this->title.'</h1><div id="content">', null, false);
  }
  
  /**
   * Output
   */
  private function output($content, $class = 'info', $html = true) {
    if ($html) {
      print '<div class="'.$class.'">'.$content.'</div>';
    } else {
      print $content;
    } 
    flush();
  }
  
  /**
   * Translate function (ported from Drupal)
   */
  private function t($string, $args = array()) {
    if ($this->langauge) {
      if (is_file('lang/'.$this->langauge.'.php')) {
        include('lang/'.$this->langauge.'.php');
        $string = $local[$string];
      }
    }
    
    if (empty($args)) {
      return $string;
    }
    else {
      foreach ($args as $key => $value) {
        switch ($key[0]) {
          case '@':
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
    while (($file = readdir($handle)) !== false) {
      if ($file == '.' || $file == '..') {
        continue;
      }
      $filepath = $dir == '.' ? $file : $dir . '/' . $file;
      if (is_link($filepath)) {
        continue;
      }
      if (is_file($filepath)) {
        $this->files[] = $filepath;
      }
      else if (is_dir($filepath)) {
        $this->listdir($filepath);
      }
    }
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
    $units = explode(' ','B KB MB GB TB PB');
    for ($i = 0; $size > $mod; $i++) {
        $size /= $mod;
    }
    return round($size, 2) . ' ' . $units[$i];
  }
}

$shelldetector = new shellDetector(array('extension'=>'.php|.txt'));
$shelldetector->start();
?>
