<?php
/**
 * Web Shell Detector v1.51
 * Web Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>
 * https://github.com/emposha/PHP-Shell-Detector
 */

//no timeout
set_time_limit(0);

//own error handler
set_error_handler( array("shellDetector", "error_handler"));

// set the default timezone to use.
date_default_timezone_set('GMT');

$shelldetector = new shellDetector(array('extension' => array('php', 'txt'), 'hidesuspicious' => false, 'authentication' => null));
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
  private $hidesuspicious = false; //settings: hide suspicious files
  
  //system variables
  private $_output = ''; //system variable used with is_cron
  private $_files = array(); //system variable hold all scanned files
  private $_badfiles = array(); //system variable hold bad files
  private $fingerprints = array(); //system: hold shells singnatures
  private $_title = 'Web Shell Detector'; //system: title
  private $_version = '1.52'; //system: version of shell detector
  private $_regex = '%(preg_replace.*\/e|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)%'; //system: regex for detect Suspicious behavior
  private $_public_key = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JR2ZNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRRDZCNWZaY2NRN2dROS93TitsWWdONUViVU4NClNwK0ZaWjcyR0QvemFrNEtDWkZISEwzOHBYaS96bVFBU1hNNHZEQXJjYllTMUpodERSeTFGVGhNb2dOdzVKck8NClA1VGprL2xDcklJUzVONWVhYUQvK1NLRnFYWXJ4bWpMVVhmb3JIZ25rYUIxQzh4dFdHQXJZWWZWN2lCVm1mRGMNCnJXY3hnbGNXQzEwU241ZDRhd0lEQVFBQg0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tDQo='; //system: public key to encrypt file content
  private $_self = '';
  
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
      $this->_self = basename(__FILE__);
    }
    
    if ($this->authentication != null) {
      if ((!isset($_SERVER['PHP_AUTH_USER']) || (isset($_SERVER['PHP_AUTH_USER']) && $_SERVER['PHP_AUTH_USER'] != $this->authentication['username'])) || (!isset($_SERVER['PHP_AUTH_PW']) ||(isset($_SERVER['PHP_AUTH_PW']) && $_SERVER['PHP_AUTH_PW'] != $this->authentication['password']))) {
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
    	$context = stream_context_create(array('http' => array('timeout' => 30)));
    	$this->fingerprints = unserialize(base64_decode(file_get_contents('shelldetect.db', 0, $context)));
    }

    if ($this->remotefingerprint) {
      $this->fingerprints = unserialize(base64_decode(file_get_contents('https://raw.github.com/emposha/PHP-Shell-Detector/master/shelldetect.db')));
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
   * Update function get latest update
   */
  private function update() {
    if($this->version()) {
    	$context = stream_context_create(array('http' => array('timeout' => 30)));
    	$content = file_get_contents('https://raw.github.com/emposha/PHP-Shell-Detector/master/shelldetect.db', 0, $context);
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
  	$context = stream_context_create(array('http' => array('timeout' => 10)));
    $version = isset($this->fingerprints['version']) ? $this->fingerprints['version'] : 0;
    $server_version = file_get_contents('https://raw.github.com/emposha/PHP-Shell-Detector/master/version/db', 0, $context);
    if(strlen($server_version) != 0 && intval($server_version) != 0 && (intval($server_version) >  intval($version))) {
      $this->output($this->t('New version of shells signature database found. Please update!'), 'error');
      return true;
    } else if(strlen($server_version) == 0 || intval($server_version) == 0) {
      $this->output($this->t('Cant connect to server! Version check failed!'), 'error');
    }
		//check application version
		$app_version = floatval($this->_version);
		$server_version = file_get_contents('https://raw.github.com/emposha/PHP-Shell-Detector/master/version/app', 0, $context);
    if(strlen($server_version) != 0 && floatval($server_version) != 0 && (floatval($server_version) >  $app_version)) {
      $this->output($this->t('New version of application found. Please update!'), 'error');
      return true;
    } else if(strlen($server_version) == 0 || intval($server_version) == 0) {
      $this->output($this->t('Cant connect to server! Application version check failed!'), 'error');
    }
    return false;
  }
  
  /**
   * Scan function executer
   */
  private function filescan() {
    $this->output($this->t('Starting file scanner, please be patient file scanning can take some time.'));
    $this->output($this->t('Number of known shells in database is: '). (count($this->fingerprints) - 1));
    $this->output('<div class="info">' . $this->t('Files found:') . '<span class="filesfound">', null, false);
    $this->listdir($this->directory);
    $this->output('</span></div>', null, false);
    if(count($this->_files) > $this->filelimit) {
      $this->output($this->t('File limit reached, scanning process stopped.'));
    }
    $this->output($this->t('File scan done, we have: @count files to analize', array("@count" => count($this->_files))));
     if ($this->hidesuspicious) {
      $this->output($this->t('Please note suspicious files information will not be displayed'), 'error');
    }
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
    foreach($this->_files as $file) {
      $content = file_get_contents($file);
      $base64_content = base64_encode($content);
      $shellflag = $this->unpack($file, $content, $base64_content);
      
      if ($shellflag !== false) {
        $this->fileInfo($file, $base64_content);
        $this->output('<dt>' . $this->t('Fingerprint:') . '</dt><dd class="red">' . $this->t('Positive, it`s a ') . $shellflag . '</dd></dl></dd></dl>', null, false);
      } else if ($this->hidesuspicious !== true) {
        if(preg_match_all($this->_regex, $content, $matches)) {
          $this->fileInfo($file, $base64_content);
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
          $key = $this->t('Negative').' <small class="source_submit_parent">('.$this->t('if wrong').' <a href="#" id="m_' . md5($file) . '" class="source_submit">'.$this->t('submit file for analize').'</a>)</small>';
          $key .= '<div id="wrapform_' . md5($file) . '" class="hidden"><iframe border="0" scrolling="no" class="hidden" id="iform_' . md5($file) . '" name="iform_' . md5($file) . '" src="http://www.websecure.co.il/phpshelldetector/api/loader.html" />"></iframe>';
          $key .= '<form id="form_' . md5($file) . '" target="iform_' . md5($file) . '" action="http://www.websecure.co.il/phpshelldetector/api/?task=submit&ver=2" method="post">';
          $key .= '<dl><dt>'. $this->t('Submit file').' '.$file.'</dt><dd>';
          $key .= '<dl><dt class="submit_email">'.$this->t('Your email').'<br /><span class="small">'.$this->t('(in case you want to be notified):').'</span></dt><dd class="submit_email_field"><input type="text" name="email" id="email" value="" class="text ui-widget-content ui-corner-all" /></dd></dl></dd></dl>';
          if (function_exists('openssl_public_encrypt')) {
            if (openssl_public_encrypt($base64_content, $crypted_data, base64_decode($this->_public_key))) {
              $key .= '<input type="hidden" name="crypted" value="1" /><input type="hidden" name="code" value="' . base64_encode($crypted_data) . '" /></form>';
            } else {
              $key .= '<input type="hidden" name="code" value="' . $base64_content . '" /></form>';
            }
          } else {
            $key .= '<input type="hidden" name="code" value="' . $base64_content . '" /></form>';
          }
          $key .= '</div>';
          $this->output('<dt>' . $this->t('Fingerprint:') . '</dt><dd class="green">' . $key . '</dd></dl></dd></dl>', null, false);
          $counter++;
        }
      } else {
        if(preg_match_all($this->_regex, $content, $matches)) {
          $counter++;
        }
      }
    }
    $this->output('', 'clearer');
    $this->output($this->t('<strong>Status</strong>: @count suspicious files found and @shells shells found', array("@count" => $counter, "@shells" => count($this->_badfiles) ? '<strong>'.count($this->_badfiles).'</strong>' : count($this->_badfiles))), (count($this->_badfiles) ? 'error' : 'success'));
  }

	/**
	 * Show file information
	 */
  private function fileInfo($file, $base64_content) {
    $this->output('<dl><dt>' . $this->t('Suspicious behavior found in:') . ' ' . basename($file) . '<span class="plus">-</span></dt>', null, false);
    $this->output('<dd><dl><dt>' . $this->t('Full path:') . '</dt><dd>' . $file . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Owner:') . '</dt><dd>' . fileowner($file) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Permission:') . '</dt><dd>' . substr(sprintf('%o', fileperms($file)), -4) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Last accessed:') . '</dt><dd>' . date($this->dateformat, fileatime($file)) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Last modified:') . '</dt><dd>' . date($this->dateformat, filemtime($file)) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('MD5 hash:') . '</dt><dd>' . md5($base64_content) . '</dd>', null, false);
    $this->output('<dt>' . $this->t('Filesize:') . '</dt><dd>' . $this->HumanReadableFilesize($file) . '</dd>', null, false);
  }

	/**
	 * Unpacking function, main idea taken from http://www.tareeinternet.com/
	 */
	private function unpack($file, $content, $base64_content) {
		if ($flag = $this->fingerprint($file, $base64_content)) {
				return $flag;
		} else {
			$counter = 0;
			$encoded_content = preg_replace("/<\?php|\?>|<\?/", "", $content);
			$temp = array();
			if (preg_match("/(\beval\b\(gzinflate|\beval\b\(base64_decode)/", $encoded_content)) {
				while (preg_match("/\beval\((gzinflate|base64_decode)\((.*?)\);/", $encoded_content, $matches)) {
					$encoded_content = preg_replace("/<\?php|\?>|<\?|eval/", "", $encoded_content);
					$temp = $matches;
					if (isset($matches[1]) && isset($matches[2]) && strpos($matches[2], '$') === false) {
						eval("\$encoded_content = " . $matches[1] . '(' . $matches[2] . ";");
					} else if (isset($matches[1]) && isset($matches[2]) && strpos($matches[2], '$') !== false) {
						preg_match('/\$(.*?)\)/', $matches[2], $variable);
						if (isset($variable[1])) {
							preg_match('/\$' . $variable[1] . '=(.*?);/', $content, $content_match);
							if (isset($content_match[1])) {
								$content_temp = $matches[1] . '(' . str_replace('$' . $variable[1], $content_match[1], $matches[2]);
								eval("\$encoded_content = " . $content_temp.";");
							} else {
								$encoded_content = '';
							}
						} else {
							$encoded_content = '';
						}
					} else {
						$encoded_content = '';
					}
					if ($counter > 20) {
						//protect from looping
						break;
					}
					$counter++;
				}
			} else if (preg_match("/preg_replace.*\/e\"/", $encoded_content)) {
				while (preg_match("/preg_replace\((.*?)\/e(.*)\);/", $encoded_content, $matches)) {
					$encoded_content = preg_replace("/<\?php|\?>|<\?/", "", $encoded_content);
					preg_replace("/preg_replace\((.*?)\/e(.*)\);/", "", $encoded_content);
					if (isset($matches[1]) && isset($matches[2])) {
						eval("\$encoded_content = preg_replace(" . $matches[1].'/' . $matches[2] . ');');
					}
					if ($counter > 20) {
						//protect from looping
						break;
					}
					$counter++;
				}
			} else {
				$encoded_content = '';
			}
			if ($encoded_content != '') {
				$encoded_content64 = base64_encode($encoded_content);
				$flag = $this->fingerprint($file, $encoded_content64);
			} else {
				$flag = false;
			}
		}
		return $flag;
	}

  /**
   * Fingerprint function
   */
  private function fingerprint($file, $content = null) {
    $key = false;
    foreach ($this->fingerprints as $fingerprint => $shell) {
      if(preg_match("/".preg_quote($fingerprint, '/')."/", $content)) {
        $key = $shell;
        $this->_badfiles[] = $file;
        break;
      }
    }
    return $key;
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
    $style = '<style type="text/css" media="all">body{background-color:#ccc;font:13px tahoma,arial;color:#151515;direction:ltr}h1{text-align:center;font-size:24px}dl{margin:0;padding:0}#content{width:1024px;margin:0 auto;padding:35px 40px;border:1px solid #e8e8e8;background:#fff;overflow:hidden;-webkit-border-radius:7px;-moz-border-radius:7px;border-radius:7px}dl dt{cursor:pointer;background:#5f9be3;color:#fff;float:left;font-weight:700;margin-right:10px;width:99%;position:relative;padding:5px}dl dt .plus{position:absolute;right:4px}dl dd{margin:2px 0;padding:5px 0}dl dd dl{margin-top:24px;margin-left:60px}dl dd dl dt{background:#4fcba3!important;width:180px!important}.error{background-color:#ffebe8;border:1px solid #dd3c10;padding:4px 10px;margin:5px 0}.success{background-color:#fff;border:1px solid #bdc7d8;padding:4px 10px;margin:5px 0}.info{background-color:#fff9d7;border:1px solid #e2c822;padding:4px 10px;margin:5px 0}.clearer{clear:both;height:0;font-size:0}.hidden{display:none}.green{font-weight:700;color:#92b901}.red{font-weight:700;color:#dd3c10}.green small{font-weight:400!important;color:#151515!important}.filesfound {position: relative}.files {position: absolute;left:4px;background-color:#FFF9D7}iframe{border:0px;height:24px;width:100%}.small{font-size: 10px;font-weight:normal;}.ui-widget-content dl dd dl {margin-left: 0px !important;}.ui-widget-content input {width: 310px;margin-top: 4px;}.submit_email {width: 190px !important;}.submit_email_field{float: left; width: 100px !important;}</style>';
    $script = 'function init(){$("dt").click(function(){var text=$(this).children(".plus");if(text.length){$(this).next("dd").slideToggle();if(text.text()=="+"){text.text("-")}else{text.text("+")}}});$(".showline").click(function(){var id="li"+$(this).attr("id");$("#"+id).dialog({height:440,modal:true,width:600,title:"Source code"});return false});$(".source_submit").click(function(){var id="for"+$(this).attr("id");$("#wrap"+id).dialog({autoOpen:false,height:200,width:550,modal:true,resizable: false,title:"File submission",buttons:{"Submit file":function(){if($(".ui-dialog-content form").length){$("#i"+id).removeClass("hidden");$("#"+id).submit();$(".ui-dialog-content form").remove()}else{alert("This file already submited")}}}});$("#wrap"+id).dialog("open");return false})}$(document).ready(init);';
    $this->output('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><meta name="robots" content="noindex"><title>Web Shell Detector</title>' . $style . '<link rel="stylesheet" href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/themes/base/jquery-ui.css" type="text/css" media="all" /><script src="http://ajax.googleapis.com/ajax/libs/jquery/1/jquery.min.js" type="text/javascript" charset="utf-8"></script><script src="https://ajax.googleapis.com/ajax/libs/jqueryui/1.8.13/jquery-ui.min.js" type="text/javascript" charset="utf-8"></script><script type="text/javascript">' . $script . '</script></head><body><h1>' . $this->_title . ' v'.$this->_version.'</h1><div id="content">', null, false);
  }

  /**
   * Output
   */
  static function output($content, $class ='info', $html = true) {
    if(isset($this) && $this->is_cron) {
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
          $extension = pathinfo($filepath);
          if (is_string($this->extension) && $this->extension == '*') {
						$this->_files[] = $filepath;
					} else {
	          if(isset($extension['extension']) && in_array($extension['extension'], $this->extension)) {
	            if ($this->_self != basename($filepath)) {
	              $this->_files[] = $filepath;
	            }
	          }
					}
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
  static public function error_handler($errno, $errstr, $errfile, $errline) {
    switch ($errno) {
			case E_USER_WARNING:
      case E_USER_ERROR :
      case E_USER_NOTICE :
			default:
        shellDetector::output('<strong>Error: </strong>' . $errstr.' line: '.$errline, 'error');
        break;
    }
  }
}
?>