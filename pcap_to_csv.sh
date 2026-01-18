#!/usr/bin/env bash

mkdir -p flows
for f in captures/*.pcap; do
  ./build/pcap2flows "$f" "flows/$(basename "$f" .pcap).csv"
done