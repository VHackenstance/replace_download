<h3>REPLACE DOWNLOAD</h3>
<h4>Intercept Target download and replace it with Spoof file.</h4>
<p>Unable to get this working with OWASP Juice Shop Locally http://localhost:3000/</p>
<h4>Basic Stuff:</h4>
<p>Tested and works so far with OWASP Juice Shop online
    <br/>
    <b>http://demo.owasp-juice.shop/ftp/quarantine</b>
    <br/>
    When it is not broken lol.
</p>
<ol>
    <li>Enable port forwarding (1) just in case you want to remote.
        <br/> It doesn't seem to make a difference.
    </li>
    <li>
        Set ALL iptables - INPUT, OUTPUT, FORWARD. 
        <br />
        There is not conflict local vs remote.
    </li>
    <li>This only works with arp_spoof.py, which sets you onPath.
    <br />
    Or, PitM (Person in the Middle) hehe.
    </li>
    <li>
        Flush ip_tables when your finished. 
        <br/>
        But I sometimes just leave them running, this is my attack machine.
        <br />
        And it's a VM after all.
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

