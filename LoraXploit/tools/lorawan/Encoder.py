# Encoder.py
# Updated to encode only minute-of-hour (0–59)

import argparse
import struct
import base64

def encode_float_le(value):
    # Convert float to little-endian 4-byte format
    return struct.pack('<f', value)

def encode_minute_of_hour(time_str):
    try:
        hours, minutes = map(int, time_str.strip().split(':'))
        if not (0 <= minutes <= 59):
            raise ValueError("Minutes must be in range 0–59.")
        return minutes
    except Exception as e:
        raise ValueError("Invalid time format. Use HH:MM.") from e

def main():
    parser = argparse.ArgumentParser(description="Encode GPS coordinates and time into a 10-byte payload.")
    parser.add_argument('--lat', type=float, required=True, help='Latitude (float)')
    parser.add_argument('--lon', type=float, required=True, help='Longitude (float)')
    parser.add_argument('--time', type=str, required=True, help='Time in HH:MM format')
    parser.add_argument('--valid', action='store_true', help='Set if GPS data is valid')

    args = parser.parse_args()

    # Encode latitude and longitude
    lat_bytes = encode_float_le(args.lat)
    lon_bytes = encode_float_le(args.lon)

    # Encode only the minute of the hour (0–59)
    minute_of_hour = encode_minute_of_hour(args.time)
    time_byte = struct.pack('B', minute_of_hour)

    # Encode GPS validity flag
    valid_byte = struct.pack('B', 1 if args.valid else 0)

    # Create 10-byte payload
    payload = lat_bytes + lon_bytes + time_byte + valid_byte

    print(f"\nHex: {payload.hex()}")
    print(f"Base64: {base64.b64encode(payload).decode()}\n")

if __name__ == '__main__':
    main()
