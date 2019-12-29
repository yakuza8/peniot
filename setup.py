from distutils.core import setup

setup(name='Peniot',
      version='1.0',
      description='Penetration Testing Tool for IoT devices',
      author='Berat Cankar,Bilgehan Bingol,Ebru Celebi,Dogukan Cavdaroglu',
      packages=['src', 'src.BLE', 'src.MQTT', 'src.RPL'],
      requires=['bluepy', 'paho.mqtt', 'scapy', 'pyshark', 'paho-mqtt', 'kivy', 'coapthon', 'Cython', 'pygame', 'pika', 'fpdf', 'enum'],
      classifiers=['Programming Language :: Python :: 2.7.9']
)
