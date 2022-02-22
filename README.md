# PENIOT: Penetration Testing Tool for IoT

#### Table of Contents
* [Project Description](#Project-Description)
    * [What is PENIOT?](#What-is-PENIOT)
    * [Why is PENIOT required?](#Why-is-PENIOT-required)
    * [What does PENIOT provide?](#What-does-PENIOT-provide)
* [Build Instructions](#Build-Instructions)
* [Documentation](#Documentation)
* [Testing](#Testing)
* [Contributors](#Contributors)
* [Developer's Note](#Developers-Note)
* [Project Poster](#Project-Poster)

## Project Description

### What is PENIOT?

[PENIOT](https://senior.ceng.metu.edu.tr/2019/peniot/) is a penetration testing tool for Internet of Things (IoT) devices. 
It helps you to test/penetrate your devices by targeting their internet connectivity
with different types of security attacks. In other words, you can expose your device
to both active and passive security attacks. After deciding target device and necessary
information (or parameters) of that device, you can perform active security attacks like
altering/consuming system resources, replaying valid communication units and so on.
Also, you can perform passive security attacks such as breaching of confidentiality of
important information or reaching traffic analysis. Thanks to PENIOT, all those operations
can be semi-automated or even fully automated. In short, PENIOT is a package/framework for
targeting IoT devices with protocol based security attacks.

Also, it gives you a baseline structure for your further injections of new security attacks
or new IoT protocols. One of the most important features of PENIOT is being extensible.
By default, it has several common IoT protocols and numerous security attacks related to
those protocols. But, it can be extended further via exporting basic structure of internally
used components so that you can develop your attacks in harmony with the internal structure
of the PENIOT.

### Why is PENIOT required?

The IoT paradigm has experienced immense growth in the past decade, with billions of devices
connected to the Internet. Most of these devices lack even basic security measures due to
their capacity constraints and designs made without security in mind due to the shortness
of time-to-market. Due to the high connectivity in IoT, attacks that have devastating
effects in extended networks can easily be launched by hackers through vulnerable devices.

Up until now, penetration testing was done manually if it was not ignored at all.
This procedure made testing phase of devices very slow. On the other hand, the firms which
produce IoT devices should always be up to date on testing their devices in terms of
reliability, robustness as well as their provided functionalities since being exposed to
security attacks by malicious people could cause unexpected impacts on end-users.
The main aim of PENIOT is to accelerate the process of security testing. It enables you to
figure out security flaws on your IoT devices by automating the time consuming penetration
testing phase.

### What does PENIOT provide?

First of all, PENIOT provides novelty. It is one of the first examples of penetration testing
tools on IoT field. There are only one or two similar tools which are specialized on IoT,
but they are still on development phase, so not completed yet.

Since the number of IoT devices is increasing drastically, IoT devices become more and more
common in our daily life. Smart homes, smart bicycles, medical sensors, fitness trackers,
smart locks and connected factories are just a few examples of IoT products. Given this,
we felt the need to choose some of the most commonly used IoT protocols to plant into PENIOT
by default. We chose the following protcols as the default IoT protocols included in the
PENIOT. These IoT protocols are tested with various types of security attacks such as DoS,
Fuzzing, Sniffing and Replay attacks. 

Following protocols are currently supported:
* Advanced Message Queuing Protocol ([AMQP](https://www.amqp.org/))
* Bluetooth Low Energy ([BLE](https://www.bluetooth.com/))
* Constraint Application Protocol ([CoAP](https://coap.technology/))
* Message Queuing Telemetry Transport ([MQTT](http://mqtt.org/))

Moreover, it enables you to export internal mainframe of its own implemented protocol and
attacks to implement your own protocols or attacks. Also, you can extend already existing
protocols with your newly implemented attacks. And lastly, it provides you an easy to use,
user friendly graphical user interface. 

## Build Instructions
Firstly, you need to have Python's **setuptools** module installed in your machine. Also,
you need to install **python-tk** and **[bluepy](https://github.com/IanHarvey/bluepy)**
before installation and build.

In short, you need the followings before running installation script.
* setuptools
* python-tk
* bluepy

> Note that it is suggested to have a separate virtual environment particularly created
> for Peniot since the dependent libraries are pretty old and can cause some trouble to
> install them among your existing external libraries

You can build project in your local by executing following codes.
```shell
$ git clone git@github.com:yakuza8/peniot.git
$ cd peniot
$ python setup.py install
```
Even if we try to provide you up-to-date installation script, there can be some missing parts in
it since the project cannot be maintained so long. Please inform us if there is any problem
with installation.

**Important Note**: You need to have [Radamsa](https://gitlab.com/akihe/radamsa) installed
in your machine in order for generating fuzzing payloads in fuzzing attacks.  

## Execution

You can run Peniot via command line or your favorite IDE after setting up a virtual environment and 
installing the necessary libraries described above.

```shell
$ python src/peniot.py
```

After running this command, you should see an user interface appeared. Then you can explore the tool
by yourself.

## Documentation
You can find *Design Overview Document* and *Final Design Document* under the **resources/documents** folder.
Several diagrams are attached under the **resources/diagrams** folder. Here is the simplest
representation of how PENIOT is separated modules and how it is designed.

<p align="center">
<img src="/resources/diagrams/peniot_structure_component_diagram.png">
</p>

## Testing
Most of the attacks have their own sample integration tests under their attack scripts. In
order to run those tests, you need to have a running program for the target protocol. We try to
provide you with example programs for each protocol where one can find server/client scripts
under each protocol's **examples** directory. 

## Contributors
This project is contributed by the following project members:
- Berat Cankar
- Bilgehan Bingöl
- Doğukan Çavdaroğlu
- Ebru Çelebi

and is supervised by **Pelin Angın**.

## Developer's Note
Firstly, let me thank you for visiting our project site. We tried to provide you how one can
penetrate and hack IoT devices over the protocols they use thanks to end-to-end security attacks.
Our main purpose is to hack those devices with generic security attacks. One can simply find
specific attacks for any protocol, but as I said ours was to provide generic and extendable
penetration framework. 

Secondly, PENIOT is developed with **Python2.7**. And our code maybe had gone into *legacy state*.
But nevertheless, we wanted to share it to public so that anyone could get insight and
inspiration to develop their own penetration tools, that is what makes us happy if it could happen.

Thirdly, we also will try to port our tool into **Python3** if we can spare necessary time for that.
When it happens, we will inform it from this page as well. Thanks for your attention.

Developer: @yakuza8 (Berat Cankar)

## Project Poster
<p align="center">
<img src="/resources/peniot_vectorized.svg">
</p>
