from Old_Parts.MQTT.MQTTTest import MQTTTest
from protocols.BLE.BLETest import BLETest

protocols = ["BLE", "MQTT", "RPL"]

#Later on we completed attacks, attacks and attack names can be gotten dynamically depending on the architecture.
BLE_attacks = ["Attacks on the Pairing Algorithm", "Replay Attack", "Fuzzing Attack"]
MQTT_attacks = ["Denial of Service Attack", "Replay Attack", "Fuzzing Attack", "Custom Attacks"]

protocol_attacks = {
        "BLE" : BLE_attacks,
        "MQTT" : MQTT_attacks,
    }

def test_factory(protocol_name):
    protocol_name = protocol_name.lower()
    if (protocol_name == "ble"):
        return BLETest()
    if (protocol_name == "mqtt"):
        return MQTTTest()
    return None
    

def select_protocol():
    #return: protocol name that user picked
    for p in range(len(protocols)):
        print p + 1, ":", protocols[p]
    print "e : Exit"

    inp = raw_input("Please pick the number of the name of the protocol to be tested from above: ")

    if inp is "e":
        exit_peniot()
    
    #GROUP: entering other things?
    return protocols[int(inp)-1]

def select_attack(protocol_name):
    #protocol_name: name of the protocol whose attacks to be listed
    #return: attack name that user picked
    attacks = protocol_attacks[protocol_name]
    for p in range(len(attacks)):
        print p + 1, ":", attacks[p]
    print "e : Exit"

    inp = raw_input("Please pick the number of the attack to be tested from above: ")

    if inp is "e":
        exit_peniot()
    
    #GROUP:entering other things?
    return attacks[int(inp)-1]

def exit_peniot():
    print "Good Bye"
    exit()

if __name__ == '__main__':
    welcome = """ ___ ___  _  _  _  _ ___ 
| o \ __|| \| || |/ \_ _|
|  _/ _| | \\\ || ( o ) | 
|_| |___||_|\_||_|\_/|_|
"""
    print welcome

    protocol_name = select_protocol()
    attack_name = select_attack(protocol_name)

    test_object = test_factory(protocol_name)
    if test_object is not None:
        test_object.run_test(attack_name)
