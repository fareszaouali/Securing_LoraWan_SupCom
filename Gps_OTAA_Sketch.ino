#include <LoRaWan.h> 

#include "TinyGPS++.h" 

 

TinyGPSPlus gps; 

char buffer[256]; 

 

void setup(void) { 

    SerialUSB.begin(115200); 

    while (!SerialUSB); 

 

    // Initialize LoRaWAN 

    lora.init(); 

    lora.setDeviceReset(); 



    // LoRaWAN OTAA Join 

    while (!lora.setOTAAJoin(JOIN)); 

    SerialUSB.println("Joined LoRaWAN!"); 

 

    // Initialize GPS 

    Serial2.begin(9600); 

} 

 

void loop(void) { 

    // Read and process GPS data 

    while (Serial2.available() > 0) { 

        gps.encode(Serial2.read()); 

    } 

 

    // Create optimized payload: 

    // - 4 bytes: lat (float) 

    // - 4 bytes: lng (float) 

    // - 1 byte : time in minutes since midnight (uint16 could be used if you want higher resolution) 

    // - 1 byte : validity flag 

    uint8_t payload[10]; 

    float lat, lng; 

    uint16_t minutesSinceMidnight = 0; 

    uint8_t gpsValidFlag = 0; 

 

    if (gps.location.isValid() && gps.time.isValid()) { 

        lat = gps.location.lat(); 

        lng = gps.location.lng(); 

        gpsValidFlag = 1; 

        minutesSinceMidnight = gps.time.hour() * 60 + gps.time.minute(); 

    } else { 

        // Send zeros if GPS is invalid 

        lat = 0.0; 

        lng = 0.0; 

        gpsValidFlag = 0; 

        minutesSinceMidnight = 0; 

        SerialUSB.println("⚠️ GPS location or time is invalid."); 

    } 

 

    memcpy(&payload[0], &lat, 4); 

    memcpy(&payload[4], &lng, 4); 

    payload[8] = (uint8_t)(minutesSinceMidnight & 0xFF);  // Only using lower 8 bits to save space 

    payload[9] = gpsValidFlag; 

 

    // ✅ Debug: Reconstruct floats from payload to print correctly 

    float debugLat, debugLng; 

    memcpy(&debugLat, &payload[0], 4); 

    memcpy(&debugLng, &payload[4], 4); 

 

    SerialUSB.print("Sending binary GPS data → Lat: "); 

    SerialUSB.print(debugLat, 6); 

    SerialUSB.print(", Lng: "); 

    SerialUSB.print(debugLng, 6); 

    SerialUSB.print(", Time (min): "); 

    SerialUSB.print(minutesSinceMidnight); 

    SerialUSB.print(", Valid: "); 

    SerialUSB.println(gpsValidFlag); 

 

    // ✅ Timestamp Debug 

    SerialUSB.print("Timestamp: "); 

    SerialUSB.println(getDateTime()); 

 

    // Send payload 

    bool result = lora.transferPacket(payload, sizeof(payload)); 

    if (result) { 

        SerialUSB.println("✅ Data sent successfully!\n"); 

    } else { 

        SerialUSB.println("❌ Data send failed.\n"); 

    } 

 

    delay(10000); // Wait 10 seconds 

} 

 

// ✅ Function to Get Date/Time in ISO 8601 format 

char* getDateTime() { 

    static char dateTime[30]; 

 

    if (gps.date.isValid() && gps.time.isValid()) { 

        snprintf(dateTime, sizeof(dateTime), "%04d-%02d-%02dT%02d:%02d:%02dZ",   

                 gps.date.year(), gps.date.month(), gps.date.day(),   

                 gps.time.hour(), gps.time.minute(), gps.time.second());   

    } else { 

        snprintf(dateTime, sizeof(dateTime), "INVALID"); 

    } 

 

    return dateTime; 

} 

 