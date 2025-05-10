# Copyright (c) 2019 IOActive Inc.  All rights reserved.

import sys, argparse, os
import base64
import json
import lorawanwrapper.LorawanWrapper as LorawanWrapper


def decode(base64_payload):
    bytes_data = list(base64.b64decode(base64_payload))

    if len(bytes_data) != 10:
        return {
            "error": "Invalid payload length"
        }

    def decodeFloatLE(bytes_list, index):
        b0 = bytes_list[index]
        b1 = bytes_list[index + 1]
        b2 = bytes_list[index + 2]
        b3 = bytes_list[index + 3]
        bits = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0

        sign = 1 if ((bits >> 31) == 0) else -1
        e = (bits >> 23) & 0xFF
        m = (bits & 0x7FFFFF) << 1 if e == 0 else (bits & 0x7FFFFF) | 0x800000

        value = sign * m * (2 ** (e - 150))
        return round(value, 6)

    latitude = decodeFloatLE(bytes_data, 0)
    longitude = decodeFloatLE(bytes_data, 4)
    minutes_since_midnight = bytes_data[8]
    gps_valid = bytes_data[9] == 1

    hours = minutes_since_midnight // 60
    minutes = minutes_since_midnight % 60
    formatted_time = "{:02d}:{:02d}".format(hours, minutes)

    from datetime import datetime
    iso_timestamp = datetime.utcnow().isoformat() + "Z"

    return {
        "latitude": latitude,
        "longitude": longitude,
        "gps_valid": gps_valid,
        "device_time": formatted_time,
        "published_time": iso_timestamp
    }


if __name__ == '__main__':

    # TEST PHYPAYLOADS

    # A JoinRequest: AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU=
    # A JoinAccept: IB1scNmwJRA32RfMbvwe3oI=
    # An UnconfirmedDataUp: QMTBfwGCEQADBV3/YTIQt7ibgXm3ExKn3caL453u5PTAj/EUU+UoeTTVUg==
    # An UnconfirmedDataDown: YMTBfwGFNwADJP//Ab5NjL8=

    try:
        print("************************************************************")
        print("*{:^58}*".format(""))
        print("*{:^58}*".format("LoraXploit Framework"))
        print("*{:^58}*".format(f"{sys.argv[0]}"))
        print("*{:^58}*".format(""))
        print("*{:^58}*".format("Master CS 2024/2025 - Sup'COM"))
        print("*{:^58}*".format("Authors: Fares Zaouali & Nour Elhouda Lajnef"))
        print("*{:^58}*".format(""))
        print("************************************************************")
        print("*{:^58}*".format(""))
        print("*{:^58}*".format("Based on LoRaWAN Security Framework by IOActive Inc."))
        print("*{:^58}*".format("Modified for educational use under academic project."))
        print("*{:^58}*".format(""))
        print("************************************************************")
        parser = argparse.ArgumentParser(description='This script parses and prints a single LoRaWAN PHYPayload data in Base64. It does the inverse as packetCrafter.py, so the output of that script can be used here and vice-versa.')

        requiredGroup = parser.add_argument_group('Required arguments')
        requiredGroup.add_argument("-d", "--data",
                                   help='Base64 data to be parsed. eg. -d AE0jb3GsOdJVAwD1HInrJ7i3yXAFxKU=',
                                   default=None,
                                   required=True
                                   )
        parser.add_argument("-k", "--key",
                            help='Enter a device AppKey or AppSKey depending on the packet to be decrypted (join accept or data packet). Must be in hex format, a total of 32 characters / 16 bytes. eg. 00112233445566778899AABBCCDDEEFF',
                            default=None)

        options = parser.parse_args()
        parsed_result_str = LorawanWrapper.printPHYPayload(options.data, options.key)
        print("Parsed data: %s \n" % parsed_result_str)

        # Try decoding the frmPayload
        try:
            parsed_result = json.loads(parsed_result_str)
            frm_payload = parsed_result['macPayload']['frmPayload'][0]['bytes']
            decoded_output = decode(frm_payload)
            print("Decoded Payload:", decoded_output)
        except Exception as e:
            print("Error decoding payload:", str(e))

    except KeyboardInterrupt:
        exit(0)
