print "Checking whether we have necessary dependencies installed..."

try:
    import paho.mqtt

    print "[+] You have paho-mqtt module installed."
except ImportError:
    print "[-] You have to install paho.mqtt module"
    print "\tHint: sudo -H pip install paho-mqtt"

try:
    import bluepy

    print "[+] You have bluepy module installed."
except ImportError:
    print "[-] You have to install bluepy module"
    print "\tHint: sudo -H pip install bluepy"

try:
    import coapthon

    print "[+] You have coapthon module installed."
except ImportError:
    print "[-] You have to install coapthon module"
    print "\tHint: sudo -H pip install coapthon"

try:
    import Cython

    print "[+] You have Cython module installed."
except ImportError:
    print "[-] You have to install Cython module"
    print "\tHint: sudo -H pip install Cython"

try:
    import pygame

    print "[+] You have pygame module installed."
except ImportError:
    print "[-] You have to install pygame module"
    print "\tHint: sudo -H pip install pygame"

try:
    import pika

    print "[+] You have pika module installed."
except ImportError:
    print "[-] You have to install pygame module"
    print "\tHint: sudo -H pip install pika"
