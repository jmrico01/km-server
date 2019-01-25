import datetime
import os

import cson

print("migrating")

tagOrder = [
	"author",
	"date",
	"title",
	"images",
	"video",
	"content"
]

DIR_PATH = "./data/blog"

for fileName in os.listdir(DIR_PATH):
	if fileName.endswith(".xml"):
		filePath = os.path.join(DIR_PATH, fileName)
		os.remove(filePath)

for fileName in os.listdir(DIR_PATH):
	filePath = os.path.join(DIR_PATH, fileName)
	if filePath.endswith(".cson"):
		with open(filePath, "r") as file:
			contents = file.read()
			parsed = cson.loads(contents)

		xmlStr = ""
		xmlStr += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\n<root>\n\n"
		dateStr = ""
		for tag in tagOrder:
			if tag in parsed:
				tagData = parsed[tag]
				if tag == "images":
					if len(tagData) == 0:
						continue
				else:
					if tag == "date":
						dateStr = tagData
					if len(tagData.strip()) == 0:
						continue

				xmlStr += "<{}>\n{}\n</{}>".format(tag, tagData, tag)
		xmlStr += "\n\n</root>"

		date = datetime.datetime.strptime(dateStr, "%b %d, %Y")
		outFileName = date.strftime("%Y-%m-%d") + ".xml"
		outFilePath = os.path.join(DIR_PATH, outFileName)
		with open(outFilePath, "w") as outFile:
			outFile.write(xmlStr)

		print("{} -> {}".format(filePath, outFilePath))