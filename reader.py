import csv

def reader(path):
    with open(path,"r",encoding="utf-8")as r1:
        return  list(csv.reader(r1))
