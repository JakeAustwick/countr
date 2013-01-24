This project allows one to count stuff over HTTP, then graph it, also over HTTP.

It is very alpha, but potentially useful to some now.

#Credits

This product includes GeoLite data created by MaxMind, available from
http://maxmind.com/

Jake, for some work on this.
LWB, for some ideas.

#Deloyment

Best way to try this out:
Signup to heroku.
Install heroku toolbelt.
git clone this repo.
run heroku.sh

#How to Use
##Recording Data

hit /record with a HTTP GET.

There are several features that make sense when a user's browser is hitting countr.
###GeoIP
By passing geoip=true in your record request, countr will automatically lookup the client's IP address in the included MaxMind database, then extract the client's country, region and city, including them as dimensions.

###Transparent Pixels
For some tracking, pixels, also known as [web bugs](http://en.wikipedia.org/wiki/Web_bug) are often utilized. To create your own pixel with countr, create a countr record URL, but change the "/record" to "/pixel". Countr will then return a transparent 1px * 1px gif. Include this on your web pages in an <img> tag.

###Redirects
If you wish to track traffic through countr, it can be made to issue a redirect to an arbritary URL. Simply pass "redirect_url": "any_url" as a dimension, then a 302 redirect will be issued to "any_url".

#Known bugs

For geoip, country works, but city and region do not work.