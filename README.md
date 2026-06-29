<h3>REPLACE DOWNLOAD</h3>
<h4>Intercept Target download and replace it with Spoof file.</h4>
<h4>Basic Stuff:</h4>
<p>Tested and works so far with OWASP Juice Shop online
    <br/>
    <b>http://demo.owasp-juice.shop/ftp/quarantine</b>
    <br/>
    When it is not broken lol.  Because, let us be clear.  This is the only http site, I 
    could find, which allows you to test downloads.  Due to this and many other reasons, 
    it is often broken.
<p>Does not work OWASP Juice Shop Locally http://localhost:3000/</p>
<h4>Testing in General</h4>
<p>Why test locally when you can straight up just test on Remote VM, on your lab.
</p>
<ol>
    <li>Enable port forwarding (1) just in case you want to remote.
        <br/> It doesn't seem to make a difference.
    </li>
    <li>
        Set ALL iptables - INPUT, OUTPUT, FORWARD. 
        <br />
        When using Bettercap we are using INPUT and OUTPUT
        <br />
        There is no conflict local vs remote.
    </li>
    <li>Enable arp_spoof.py, which sets you onPath.
    </li>
    <li>
        setup_environment will take care of all of this for you.
    </li>
    <li><b>Start webserver locally</b>: service apache2 start</li>
    <li>
    <b>Webroot:<b>Location of where webfiles are stored: 
    <br/>
    /var/www/html/</b>
</li>
</ol>
<p>
    <b>
        <a href="https://en.wikipedia.org/wiki/List_of_HTTP_status_codes">
            List of HTTP Status codes:
        </a>
    </b>
</p>
<p>We want to use 301 - moved permanently - to tell our response packet it is being redirected.</p>
<h4>Run on a remote computer</h4>
<h4>Bettercap works with</h4>
<ul>
<li>Linkedin.com</li>
<li>winzip.com</li>
<li>Try loading in the full address with http, this works with 
    http://7-zip.org - <b>Tested and worked to spoof download...</b>
    <br/>
    http://www.udemy.com/ - <b></b>
    <br/>
    You could try experimenting with a bunch more.
</li>
</ul>

