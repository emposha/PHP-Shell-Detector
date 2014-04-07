<?php
/**
 * Web Shell Detector v1.66
 * Web Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>
 * https://github.com/emposha/PHP-Shell-Detector
 */

set_time_limit(0);

//own error handler
set_error_handler(array("shellDetector", "error_handler"));

// set the default timezone to use.
date_default_timezone_set('GMT');

$params = array('extension' => array('php', 'txt'));
if (is_file('shelldetect.ini')) {
  $params = parse_ini_file('shelldetect.ini');
}

//static settings initialize
shellDetector::$_settings = $params;

$shelldetector = new shellDetector($params);

if ($shelldetector->isConsole()) {
  $options = getopt("d:hcb");
  if (array_key_exists("d",$options)) {
    $shelldetector->setDir($options["d"]);
  }
  if (array_key_exists("b",$options)) {
    $shelldetector->setBrief(true);
  }
  if (array_key_exists("c",$options)) {
    shellDetector::$_settings['is_cron'] = true;
    $shelldetector->setCron(true);
  }
}

$shelldetector->start();

class shellDetector {

  //settings: extensions that should be scanned
  private $extension = array('php');

  //settings: show line number where suspicious function used
  private $showlinenumbers = true;

  //settings: used with access time & modified time
  private $dateformat = "H:i:s d/m/Y";

  //settings: if I want to use other language
  private $language = '';

  //settings: if console used
  private $console = false;

  //settings: if brief info is needed
  private $brief = false;

  //settings: scan specific directory
  private $directory = '.';

  //settings: scan hidden files & directories
  private $scan_hidden = true;

  //settings: perform different task
  private $task = '';

  //settings: used with is_cron(true) file format for report file
  private $report_format = '\s\h\e\l\l\d\e\t\e\c\t\o\r\_Gi-dmY.\h\t\m\l';

  //settings: if true run like a cron (no output)
  private $is_cron = false;

  //settings: maximum files to scan (more then 30000 you should scan specific directory)
  private $filelimit = 30000;

  //settings: protect script with user & password in case to disable simply set to NULL
  private $authentication = array("username" => "admin", "password" => "protect");

  //settings: get shells signatures db by remote
  private $remotefingerprint = false;

  //settings: hide suspicious files
  private $hidesuspicious = false;

  //settings: type of file submission to review (0 - old one not secure but will work with allow_url_fopen = false, 1 - new one more secure but allow_url_fopen need to be true.)
  private $submitfile = 1;

  /*
   * System variables
   */
  //system variable used with output
  static $_settings = array();
  
  //system variable used with is_cron
  static $_output = '';

  // global counters
  private $counter = 0;
  private $suspcounter = 0;

  //system variable hold all scanned files
  private $_files = array();

  //system variable hold bad files
  private $_badfiles = array();

  //system: hold shells signatures
  private $fingerprints = array();

  //system: title
  private $_title = 'Web Shell Detector';

  //system: version of shell detector
  private $_version = '1.66';

  //system: regex for detect Suspicious behavior
  private $_regex = '%(preg_replace.*\/e|`.*?\$.*?`|\bcreate_function\b|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\bedoced_46esab\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)%';

  //system: public key to encrypt file content
  private $_public_key = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JR2ZNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRRDZCNWZaY2NRN2dROS93TitsWWdONUViVU4NClNwK0ZaWjcyR0QvemFrNEtDWkZISEwzOHBYaS96bVFBU1hNNHZEQXJjYllTMUpodERSeTFGVGhNb2dOdzVKck8NClA1VGprL2xDcklJUzVONWVhYUQvK1NLRnFYWXJ4bWpMVVhmb3JIZ25rYUIxQzh4dFdHQXJZWWZWN2lCVm1mRGMNCnJXY3hnbGNXQzEwU241ZDRhd0lEQVFBQg0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tDQo=';

  private $_self = '';

  /**
   * Constructor
   */
  function __construct($settings = null) {
    if (is_array($settings)) {
      $own = get_object_vars($this);
      foreach ($settings as $key => $value) {
        if (key_exists($key, $own) && substr($key, 0, 1) != '_') {
          $this->$key = $value;
        }
      }
      $this->_self = basename(__FILE__);
    }

    if ($this->authentication != null) {
      if ((!isset($_SERVER['PHP_AUTH_USER']) || (isset($_SERVER['PHP_AUTH_USER']) && $_SERVER['PHP_AUTH_USER'] != $this->authentication['username'])) || (!isset($_SERVER['PHP_AUTH_PW']) || (isset($_SERVER['PHP_AUTH_PW']) && $_SERVER['PHP_AUTH_PW'] != $this->authentication['password']))) {
        header('WWW-Authenticate: Basic realm="Login"');
        header('HTTP/1.0 401 Unauthorized');
        echo $this->t('Please login to continue.');
        exit ;
      }
    }

    if (isset($_GET['task'])) {
      $this->task = $_GET['task'];
    }

    if (isset($_GET['s']) && 1 == $_GET['s']) {
      $this->hidesuspicious = false;
    }

    if (file_exists('shelldetect.db')) {
      $context = stream_context_create(array('http' => array('timeout' => 30)));
      $this->fingerprints = unserialize(base64_decode(file_get_contents('shelldetect.db', 0, $context)));
    }

    if ($this->remotefingerprint) {
      $this->fingerprints = unserialize(base64_decode(file_get_contents('https://raw.github.com/emposha/PHP-Shell-Detector/master/shelldetect.db')));
    }
  }

  public function setDir($dir) {
    $this->directory = $dir;
  }

  public function setCron($val) {
    $this->is_cron = $val;
  }

  public function setBrief($val) {
    $this->brief = $val;
  }

  public function isBrief() {
    return $this->brief;
  }

  public function isConsole() {
    return $this->console;
  }

  /**
   * Start function
   */
  public function start() {
    switch ($this->task) {
      case 'sendfile':
        $this->sendfile();
        break;
      case 'getsha':
        $this->header();
        $this->filescan();
        $this->showsha();
        $this->footer();
        break;
      case 'update':
        $this->header();
        $this->update();
        $this->footer();
        break;
      default:
        $this->header();
        $this->version();
        $this->filescan();
        $this->anaylize();
        $this->footer();
        break;
    }
  }

  /**
   * Update function get latest update
   */
  private function update() {
    if ($this->version()) {
      $context = stream_context_create(array('http' => array('timeout' => 30)));
      $content = file_get_contents('https://raw.github.com/emposha/PHP-Shell-Detector/master/shelldetect.db', 0, $context);
      chmod('shelldetect.db', 0777);
      if (file_put_contents('shelldetect.db', $content)) {
        self::output($this->t('Shells signature database updated succesfully!'));
      } else {
        self::output($this->t('Cant save shells signature database please check permissions'), 'error');
      }
    } else {
      self::output($this->t('Your shells signatures database already updated!'));
    }
  }

  /**
   * Check version function
   */
  private function version() {
    $context = stream_context_create(array('http' => array('timeout' => 10, 'header' => 'Connection: close')));
    //check application version
    $app_version = floatval($this->_version);
    $server_version = file_get_contents('https://raw.github.com/emposha/PHP-Shell-Detector/master/version/app', 0, $context);
    if (strlen($server_version) != 0 && floatval($server_version) != 0 && (floatval($server_version) > $app_version)) {
      self::output($this->t('New version of application found. Please update!'), 'error');
    } else if (strlen($server_version) == 0 || intval($server_version) == 0) {
      self::output($this->t('Cant connect to server! Application version check failed!'), 'error');
    }
    
    $version = isset($this->fingerprints['version']) ? $this->fingerprints['version'] : 0;
    $server_version = file_get_contents('https://raw.github.com/emposha/PHP-Shell-Detector/master/version/db', 0, $context);
    if (strlen($server_version) != 0 && intval($server_version) != 0 && (intval($server_version) > intval($version))) {
      self::output($this->t('New version of shells signature database found. Please update!'), 'error');
      return true;
    } else if (strlen($server_version) == 0 || intval($server_version) == 0) {
      self::output($this->t('Cant connect to server! Version check failed!'), 'error');
    }
    unset($this->fingerprints['version']);
    return false;
  }

  /**
   * Send file to analyze
   */
  private function sendfile() {
    self::output('<style>.error{font-size: 14px;font-family: arial;margin: 0px;padding: 2px 6px 0px 0px;color: #DD3C10;text-align: center;}.success{font-size: 14px;font-family: arial;margin: 0px;padding: 2px 6px 0px 0px;color: #92B901;text-align: center;}</style>');
    if (isset($_POST['filename'])) {
      $filename = base64_decode($_POST['filename']);
      if (file_exists($filename)) {
        $email = isset($_POST['email']) ? $_POST['email'] : '';
        $referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : $_SERVER["SERVER_NAME"];
        $postdata = http_build_query(array('task' => 'submit', 'ver' => '2', 'code' => base64_encode(file_get_contents($filename)), 'email' => $email, 'ip' => $_SERVER['REMOTE_ADDR']));
        $context = stream_context_create(array('http' => array('method' => 'POST', 'header' => "Content-type: application/x-www-form-urlencoded\r\nReferer: " . $referer . "\r\n", 'content' => $postdata)));
        $server_version = file_get_contents('http://www.shelldetector.com/api/', 0, $context);
        self::output($server_version, 'success');
      } else {
        self::output($this->t('Cant find selected file.'), 'error');
      }
    } else {
      self::output($this->t('No file specified.'), 'error');
    }
  }

  /**
   * Scan function executer
   */
  private function filescan() {
    self::output($this->t('Starting file scanner, please be patient file scanning can take some time.'));
    self::output($this->t('Number of known shells in database is: ') . count($this->fingerprints));
    self::output('<div class="info">' . $this->t('Files found:') . '<span class="filesfound">', null, false);
    $this->listdir($this->directory);
    self::output('</span></div>', null, false);
    if ($this->filelimit>0) {
      if (count($this->_files) > $this->filelimit) {
        self::output($this->t('File limit reached, scanning process stopped.'));
      }
    }
    if ($this->filelimit>0) {
      self::output($this->t('File scan done, we have: @count files to analize', array("@count" => count($this->_files))));
    } else {
      self::output($this->t('File scan done, we have: @count files to analize', array("@count" => $this->counter)));
    }
    if ($this->hidesuspicious) {
      self::output($this->t('Please note suspicious files information will not be displayed'), 'error');
    }
  }

  /**
   * Show sha1 for found files
   */
  private function showsha() {
    foreach ($this->_files as $file) {
      self::output('<dl><dt>' . $this->t('Show sha for file:') . ' ' . basename($file) . '<span class="plus">-</span></dt>', null, false);
      self::output('<dd><dl><dt>' . $this->t('Full path:') . '</dt><dd>' . $file . '</dd>', null, false);
      self::output('<dt>' . $this->t('Sha1:') . '</dt><dd>' . sha1_file($file) . '</dd></dl></dd></dl>', null, false);
    }
    self::output('', 'clearer');
  }

  /**
   * Check files for using suspicious function
   */
  private function analyze($file) {
    $counter = 0;
    $this->counter++;
      $content = file_get_contents($file);
      $base64_content = base64_encode($content);
      $shellflag = $this->unpack($file, $content, $base64_content);

      if ($shellflag != false) {
        $this->fileInfo($file, $base64_content);
        $shellcolor = 'red';
        preg_match('#(.*)\[(.*?)\]\[(.*?)\]\[(.*?)\]#', $shellflag, $shellmatch);
        if (is_array($shellmatch) && count($shellmatch)>0) {
          $shellflag = $shellmatch[1] . '(' . $shellmatch[4] . ')';
          switch($shellmatch[3]) {
            case 1 :
              $shellcolor = 'orange';
              $shellflag .= ' ' . $this->t('please note it`s a malicious file not a shell');
              break;
            case 2:
              $shellcolor = 'orange';
              $shellflag .= ' ' . $this->t('please note potentially dangerous file (legit file but may be used by hackers)');
              break;
          }
        }
        if ($this->isConsole() && !$this->isBrief()) {
          print "$file: $shellflag\n"; 
        } 
        self::output('<dt>' . $this->t('Fingerprint:') . '</dt><dd class="' . $shellcolor . '">' . $this->t('Positive, it`s a ') . $shellflag . '</dd></dl></dd></dl>', null, false);
      } else if ($this->hidesuspicious != true) {
     	 if (preg_match_all($this->_regex, $content, $matches)) {
          $this->fileInfo($file, $base64_content);
          if ($this->showlinenumbers) {
            self::output('<dt>' . $this->t('suspicious functions used:') . '</dt><dd>', null, false);
            $_content = explode("\n", $content);
            for ($line = 0; $line < count($_content); $line++) {
              if (preg_match_all($this->_regex, $_content[$line], $matches)) {
                $lineid = md5($line . $file);
                self::output($this->_implode($matches) . ' (<a href="#" class="showline" id="ne_' . $lineid . '">' . $this->t('line:') . ($line + 1) . '</a>);', null, false);
                self::output('<div class="hidden source" id="line_' . $lineid . '"><code>' . htmlentities($_content[$line]) . '</code></div>', null, false);
              }
            }
            self::output('&nbsp;</dd>', null, false);
          } else {
            self::output('<dt>' . $this->t('suspicious functions used:') . '</dt><dd>' . $this->_implode($matches) . '&nbsp;</dd>', null, false);
          }
          $key = $this->fileprepare($file, $base64_content);
          self::output('<dt>' . $this->t('Fingerprint:') . '</dt><dd class="green">' . $key . '</dd></dl></dd></dl>', null, false);
          $this->suspcounter++;
        }
      } else {
        if (preg_match_all($this->_regex, $content, $matches)) {
          $this->suspcounter++;
        }
      }
  }

  /**
   * Check files for using suspicious function
   */
  private function anaylize() {
    foreach ($this->_files as $file) {
    	if (is_readable($file)) {
      	$this->analyze($file);
    	}  
    }
    self::output('', 'clearer');
    self::output($this->t('<strong>Status</strong>: @count suspicious files found and @shells shells found. <a href="' . $_SERVER['PHP_SELF'] . '?s=1">Rescan and show suspicious files</a>' , array("@count" => $this->suspcounter, "@shells" => count($this->_badfiles) ? '<strong>' . count($this->_badfiles) . '</strong>' : count($this->_badfiles))), (count($this->_badfiles) ? 'error' : 'success'));
  }

  /**
   * Prepare file submit function
   */
  private function fileprepare($file, $base64_content) {
    $filtered_file = filter_var($file, FILTER_SANITIZE_SPECIAL_CHARS);
    $key = $this->t('Negative') . ' <small class="source_submit_parent">(' . $this->t('if wrong') . ' <a href="#" id="m_' . md5($file) . '" class="source_submit">' . $this->t('submit file for analize') . '</a>)</small>';
    $key .= '<div id="wrapform_' . md5($file) . '" class="hidden"><iframe border="0" scrolling="no" class="hidden" id="iform_' . md5($file) . '" name="iform_' . md5($file) . '" src="http://www.shelldetector.com/api/loader.html" />"></iframe>';
    if ($this->submitfile == 0) {
      $key .= '<form id="form_' . md5($file) . '" target="iform_' . md5($file) . '" action="http://www.shelldetector.com/api/?task=submit&ver=2" method="post">';
    } else {
      $key .= '<form id="form_' . md5($file) . '" target="iform_' . md5($file) . '" action="?task=sendfile" method="post">';
    }
    $key .= '<dl><dt>' . $this->t('Submit file') . ' ' . basename($filtered_file) . '</dt><dd>';
    $key .= '<dl><dt class="submit_email">' . $this->t('Your email') . '<br /><span class="small">' . $this->t('(in case you want to be notified):') . '</span></dt><dd class="submit_email_field"><input type="text" name="email" id="email" value="" class="text ui-widget-content ui-corner-all" /></dd></dl></dd></dl>';

    if ($this->submitfile == 0) {
      if (function_exists('openssl_public_encrypt')) {
        if (openssl_public_encrypt($base64_content, $crypted_data, base64_decode($this->_public_key))) {
          $key .= '<input type="hidden" name="crypted" value="1" /><input type="hidden" name="code" value="' . base64_encode($crypted_data) . '" /></form>';
        } else {
          $key .= '<input type="hidden" name="code" value="' . $base64_content . '" />';
        }
      } else {
        $key .= '<input type="hidden" name="code" value="' . $base64_content . '" />';
      }
    }
    $key .= '<input type="hidden" name="filename" value="' . base64_encode($file) . '" /></form>';
    $key .= '</div>';
    return $key;
  }

  /**
   * Show file information
   */
  private function fileInfo($file, $base64_content) {
    $owner = fileowner($file);
    $self_owner = getmyuid();
    $permissions = substr(sprintf('%o', fileperms($file)), -4);
    if (function_exists('posix_getpwuid')) {
      $owner =  posix_getpwuid($owner);
      $owner = $owner['name'];
      $self_owner = posix_getpwuid($self_owner);
      $self_owner = $self_owner['name'];
    }
    if ($owner !== $self_owner) {
      $owner = '<span class="orange">' . $owner .'</span> <small>(' . $this->t('Please note: file have different owner') . ')</small>';
    }
    if (intval($permissions) == 777) {
      $permissions = '<span class="orange">' . $permissions .'</span> <small>(' . $this->t('Please note: file have full access permissions') . ')</small>';
    }
    $filtered_file = filter_var($file, FILTER_SANITIZE_SPECIAL_CHARS);
    self::output('<dl><dt>' . $this->t('Suspicious behavior found in:') . ' ' . basename($filtered_file) . '<span class="plus">-</span></dt>', null, false);
    self::output('<dd><dl><dt>' . $this->t('Full path:') . '</dt><dd>' . $filtered_file . '</dd>', null, false);
    self::output('<dt>' . $this->t('Owner:') . '</dt><dd>' . $owner . '</dd>', null, false);
    self::output('<dt>' . $this->t('Permission:') . '</dt><dd>' . $permissions . '</dd>', null, false);
    self::output('<dt>' . $this->t('Last accessed:') . '</dt><dd>' . date($this->dateformat, fileatime($file)) . '</dd>', null, false);
    self::output('<dt>' . $this->t('Last modified:') . '</dt><dd>' . date($this->dateformat, filemtime($file)) . '</dd>', null, false);
    self::output('<dt>' . $this->t('MD5 hash:') . '</dt><dd>' . md5($base64_content) . '</dd>', null, false);
    self::output('<dt>' . $this->t('Filesize:') . '</dt><dd>' . $this->HumanReadableFilesize($file) . '</dd>', null, false);
  }

  /**
   * Unpacking function, main idea taken from http://www.tareeinternet.com/
   */
  private function unpack($file, $content, $base64_content) {
    if ($flag = ($this->fingerprint($file, $base64_content)) ) {
      return $flag;
    } elseif ($flag = ($this->fingerprint($file, $content))) {
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
                eval("\$encoded_content = " . $content_temp . ";");
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
            eval("\$encoded_content = preg_replace(" . $matches[1] . '/' . $matches[2] . ');');
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
    
    // pre prepare all the fingerprints on the first request for optimisation.
    static $fingerprint_cache = array();
    if(empty($fingerprint_cache) === true){
        foreach ($this->fingerprints as $fingerprint => $shell){
            if (strpos($fingerprint, 'bb:') !== false) {
                $fingerprint = base64_decode(str_replace('bb:', '', $fingerprint));
            }
            $fingerprint_cache['/' . preg_quote($fingerprint, '/') . '/'] = $shell;
        }
    }
    
    foreach ($fingerprint_cache as $fingerprint => $shell) {
      if (preg_match($fingerprint, $content)) {
        # [version] => 1359928984 db content FIXME?!?!?
        if ($fingerprint == "version") break;
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
  private function _implode($array, $glue = ', ') {
    $temp = array();
    foreach ($array as $value) {
      if (is_array($value)) {
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
    self::output('</div></body></html>', null, false);
    if ($this->is_cron || $this->console) {
      $this->flush();
    }
  }

  /**
   * Output header function
   */
  private function header() {
    $style = '<style type="text/css" media="all">body{background-color:#ccc;font:13px tahoma,arial;color:#151515;direction:ltr}h1{text-align:center;font-size:24px}dl{margin:0;padding:0}#content{width:1024px;margin:0 auto;padding:35px 40px;border:1px solid #e8e8e8;background:#fff;overflow:hidden;-webkit-border-radius:7px;-moz-border-radius:7px;border-radius:7px}dl dt{cursor:pointer;background:#5f9be3;color:#fff;float:left;font-weight:700;margin-right:10px;width:99%;position:relative;padding:5px}dl dt .plus{position:absolute;right:4px}dl dd{margin:2px 0;padding:5px 0}dl dd dl{margin-top:24px;margin-left:60px}dl dd dl dt{background:#4fcba3!important;width:180px!important}.error{background-color:#ffebe8;border:1px solid #dd3c10;padding:4px 10px;margin:5px 0}.success{background-color:#fff;border:1px solid #bdc7d8;padding:4px 10px;margin:5px 0}.info{background-color:#fff9d7;border:1px solid #e2c822;padding:4px 10px;margin:5px 0}.clearer{clear:both;height:0;font-size:0}.hidden{display:none}.green{font-weight:700;color:#92b901}.red{font-weight:700;color:#dd3c10}.orange{font-weight:700;color:#ff7f00}.green small{font-weight:400!important;color:#151515!important}.filesfound {position: relative}.files {position: absolute;left:4px;background-color:#FFF9D7}iframe{border:0px;height:80px;width:100%}.small{font-size: 10px;font-weight:normal;}.ui-widget-content dl dd dl {margin-left: 0px !important;}.ui-widget-content input {width: 310px;margin-top: 4px;}.submit_email {width: 190px !important;}.submit_email_field{float: left; width: 100px !important;}#loader{position:fixed;top:25%;bottom:0;left:45%;z-index:99;display:block;text-align:center;width:100%;padding-top:125px;text-align:left;font-weight:700;text-transform:uppercase;text-indent:-20px;font-size:24px;color:#5f9be3}#circularG{position:relative;width:128px;height:128px}.circularG{position:absolute;background-color:#5f9be3;width:29px;height:29px;-webkit-border-radius:19px;-moz-border-radius:19px;-webkit-animation-name:bounce_circularg;-webkit-animation-duration:1.04s;-webkit-animation-iteration-count:infinite;-webkit-animation-direction:linear;-moz-animation-name:bounce_circularg;-moz-animation-duration:1.04s;-moz-animation-iteration-count:infinite;-moz-animation-direction:linear;border-radius:19px;-o-animation-name:bounce_circularg;-o-animation-duration:1.04s;-o-animation-iteration-count:infinite;-o-animation-direction:linear;-ms-animation-name:bounce_circularg;-ms-animation-duration:1.04s;-ms-animation-iteration-count:infinite;-ms-animation-direction:linear}#circularG_1{left:0;top:50px;-webkit-animation-delay:.39s;-moz-animation-delay:.39s;-o-animation-delay:.39s;-ms-animation-delay:.39s}#circularG_2{left:14px;top:14px;-webkit-animation-delay:.52s;-moz-animation-delay:.52s;-o-animation-delay:.52s;-ms-animation-delay:.52s}#circularG_3{top:0;left:50px;-webkit-animation-delay:.65s;-moz-animation-delay:.65s;-o-animation-delay:.65s;-ms-animation-delay:.65s}#circularG_4{right:14px;top:14px;-webkit-animation-delay:.78s;-moz-animation-delay:.78s;-o-animation-delay:.78s;-ms-animation-delay:.78s}#circularG_5{right:0;top:50px;-webkit-animation-delay:.91s;-moz-animation-delay:.91s;-o-animation-delay:.91s;-ms-animation-delay:.91s}#circularG_6{right:14px;bottom:14px;-webkit-animation-delay:1.04s;-moz-animation-delay:1.04s;-o-animation-delay:1.04s;-ms-animation-delay:1.04s}#circularG_7{left:50px;bottom:0;-webkit-animation-delay:1.17s;-moz-animation-delay:1.17s;-o-animation-delay:1.17s;-ms-animation-delay:1.17s}#circularG_8{left:14px;bottom:14px;-webkit-animation-delay:1.3s;-moz-animation-delay:1.3s;-o-animation-delay:1.3s;-ms-animation-delay:1.3s}@-webkit-keyframes bounce_circularg{0%{-webkit-transform:scale(1)}100%{-webkit-transform:scale(.3)}}@-moz-keyframes bounce_circularg{0%{-moz-transform:scale(1)}100%{-moz-transform:scale(.3)}}@-o-keyframes bounce_circularg{0%{-o-transform:scale(1)}100%{-o-transform:scale(.3)}}@-ms-keyframes bounce_circularg{0%{-ms-transform:scale(1)}100%{-ms-transform:scale(.3)}}</style>';
    $script = 'function init(){$("#loader").hide();$("dt").live("click", function(){var text=$(this).children(".plus");if(text.length){$(this).next("dd").slideToggle();if(text.text()=="+"){text.text("-")}else{text.text("+")}}});$(".showline").live("click", function(){var id="li"+$(this).attr("id");$("#"+id).dialog({height:440,modal:true,width:600,title:"Source code"});return false});$(".source_submit").live("click",function(){var id="for"+$(this).attr("id");$("#wrap"+id).dialog({autoOpen:false,height:200,width:550,modal:true,resizable: false,title:"File submission",buttons: {"Submit file to analysis": function() {if ($(".ui-dialog-content form").length) {$("#i"+id).removeClass("hidden");$("#"+id).submit();$(".ui-dialog-content form").remove();} else {alert("This file already submited");}}/*,"Submit file to Virustotal": function () {alert("Not implemented");}*/}});$("#wrap"+id).dialog("open");return false})}$(document).ready(init);';
    self::output('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><meta name="robots" content="noindex"><title>Web Shell Detector</title>' . $style . '<link rel="stylesheet" href="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.21/themes/base/jquery-ui.css" type="text/css" media="all" /><script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.js" type="text/javascript" charset="utf-8"></script><script src="http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.21/jquery-ui.js" type="text/javascript" charset="utf-8"></script><script type="text/javascript">' . $script . '</script></head><body><h1>' . $this->_title . ' v' . $this->_version . '<br />(PHP Version: ' . phpversion() .')</h1><div id="loader"><div id="circularG"><div id="circularG_1" class="circularG"></div><div id="circularG_2" class="circularG"></div><div id="circularG_3" class="circularG"></div><div id="circularG_4" class="circularG"></div><div id="circularG_5" class="circularG"></div><div id="circularG_6" class="circularG"></div><div id="circularG_7" class="circularG"></div><div id="circularG_8" class="circularG"></div></div><span class="loader_text"> ' . $this->t('Please wait') . '</span></div></div><div id="content">', null, false);
  }

  /**
   * Output
   */
  static function output($content, $class = 'info', $html = true) {
    if ((isset(self::$_settings) && isset(self::$_settings['is_cron']) && self::$_settings['is_cron']) ||
      (isset(self::$_settings) && isset(self::$_settings['console']) && self::$_settings['console'])) {
      if ($html) {
        self::$_output .= '<div class="' . $class . '">' . $content . '</div>';
      } else {
       self::$_output .= $content;
      }
    } else {
      if ($html) {
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
    if ($this->isConsole()) {
      print "$this->counter files, $this->suspcounter suspicious, ".count($this->_badfiles)." shells\n";
    } 
    if ($this->is_cron) {
      $filename = date($this->report_format, time());
      if (file_put_contents($filename, self::$_output)) {
        print $this->t('Done, report file created');
      } else {
        print $this->t('Error, report file creation failed');
      }
    }
  }

  /**
   * Translate function (ported from Drupal)
   */
  private function t($string, $args = array()) {
    if ($this->language) {
      if (is_file('lang/' . $this->language . '.php')) {
        include ('lang/' . $this->language . '.php');
        if (isset($local[$string])) {
          $string = $local[$string];
        }
      }
    }

    if (empty($args)) {
      return $string;
    } else {
      foreach ($args as $key => $value) {
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
    if (!is_dir($dir) || !is_readable($dir)) {
    return true;
  }
  $handle = opendir($dir);
    if ($this->filelimit > 0) {
      if (count($this->_files) > $this->filelimit) {
        return true;
      }
    }
    while (($file = readdir($handle)) !== false) {
      if ($file == '.' || $file == '..') {
        continue;
      }
      $filepath = $dir == '.' ? $file : $dir . '/' . $file;
      if (is_link($filepath)) {
        continue;
      }
      if (is_file($filepath)) {
        if (substr(basename($filepath), 0, 1) != "." || $this->scan_hidden) {
          $extension = pathinfo($filepath);
          if (is_string($this->extension) && $this->extension == '*') {
            if ($this->filelimit > 0) {
              $this->_files[] = $filepath;
            } else {
              $this->analyze($filepath);
            }
          } else {
            if (isset($extension['extension']) && in_array($extension['extension'], $this->extension)) {
              if ($this->_self != basename($filepath)) {
                if ($this->filelimit > 0) {
                $this->_files[] = $filepath;
                } else {
                  $this->analyze($filepath);
                }
              }
            }
          }
        }
      } else if (is_dir($filepath)) {
        if (substr(basename($filepath), 0, 1) != "." || $this->scan_hidden) {
          $this->listdir($filepath);
        }
      }
    }
    self::output('<span class="files">' . count($this->_files) . '</span>', null, false);
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
    for ($i = 0; $size > $mod; $i++) {
      $size /= $mod;
    }
    return round($size, 2) . ' ' . $units[$i];
  }

  /**
   * Own error handler
   */
  static public function error_handler($errno, $errstr, $errfile, $errline) {
    switch ($errno) {
      case E_USER_WARNING :
      case E_USER_ERROR :
      case E_USER_NOTICE :
      default :
        shellDetector::output('<strong>Error: </strong>' . $errstr . ' line: ' . $errline, 'error');
        break;
    }
  }

}
?>
