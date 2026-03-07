Arduino to Supabase Integration Guide
This guide explains how to send real-time sensor data from an Arduino/ESP32 to a Supabase database.

1. Prerequisites
Required Hardware
ESP32 or ESP8266 (Recommended for built-in Wi-Fi and HTTPS support)
Sensors (e.g., PIR, IR, or Ultrasonic for occupancy counting)
Required Libraries
In the Arduino IDE, go to Sketch -> Include Library -> Manage Libraries and install:

ArduinoJson (by Benoît Blanchon)
HTTPClient (Built-in for ESP)
WiFi (Built-in for ESP)
2. Supabase Setup
You will need three pieces of information from your Supabase Dashboard:

Project URL: Settings -> API -> Project URL
Anon Key: Settings -> API ->  anon public
Table Name: The name of the table you want to insert into.
3. Arduino Code Template
cpp
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
// --- Configuration ---
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
// Format: https://[PROJECT_ID].supabase.co/rest/v1/[TABLE_NAME]
const char* supabase_url = "https://your-id.supabase.co/rest/v1/occupancy";
const char* supabase_key = "YOUR_SUPABASE_ANON_KEY";
void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected!");
}
void sendToSupabase(int currentCount, String buildingId) {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(supabase_url);
    // Standard Supabase headers
    http.addHeader("Content-Type", "application/json");
    http.addHeader("apikey", supabase_key);
    http.addHeader("Authorization", String("Bearer ") + supabase_key);
    // return=minimal saves bandwidth and processing time
    http.addHeader("Prefer", "return=minimal");
    // Create JSON payload
    StaticJsonDocument<128> doc;
    doc["building_id"] = buildingId;
    doc["current_count"] = currentCount;
    String jsonString;
    serializeJson(doc, jsonString);
    // POST request
    int httpResponseCode = http.POST(jsonString);
    if (httpResponseCode > 0) {
      Serial.printf("Data Sent! Status: %d\n", httpResponseCode);
    } else {
      Serial.printf("Error occurred: %s\n", http.errorToString(httpResponseCode).c_str());
    }
    http.end();
  }
}
void loop() {
  // Example: Send data every 30 seconds
  int mockCount = random(10, 100); 
  sendToSupabase(mockCount, "Engineering_Block_A");
  
  delay(30000); 
}
4. Troubeshooting Tips
HTTPS/SSL: If you get -1 error, it's likely an SSL handshake issue. On ESP32, http.begin(url) usually works, but on some platforms, you may need WiFiClientSecure.
Row Level Security (RLS): If you get a 401 or 403 error, make sure your table allows INSERT for the anon role, or use your service_role key (if the device is secure).
Column Names: Ensure the keys in your StaticJsonDocument exactly match the column names in your Supabase table.

Comment
Ctrl+Alt+M
