import csv

def reader(path):
    with open(path,"r",encoding="utf-8")as r1:
        txt=list(csv.reader(r1))
