
"""
This is a script to demonstrate feasibility of creating a lightweight (~100 lines of code) Steganography program 
which can hide text data within a image using an LSB manipulation algorithm. In just a 2mb picture a bad actor 
could hide thousands of characters worth of data.

"""
# Only import for project is the PIL Image class for pixel by pixel retrieval and manipulation
import PIL
from PIL import Image
# encode() function takes image file, start offset & name to call encoded output .bmp file (which it produces)
def encode(imageFile, startOffset, outputFilename):
    #Load in image as PIL Image type object.
    image = Image.open(imageFile)
    #Extracting a list of pixel data elements with each element being a tuple of 3 integers representing 
    # the red, green and blue channels of the pixel
    pixList = list(image.getdata())
    #Set a start offset value to count how many pixels in from the start which also helps to hide size of payload
    #Calculate how many pixels this offset corresponds to
    #pixOffset = (startOffset*3)/8
    #Calculate maximum input data size taking into account the start offset value (ie if we start further into image then
    # it leaves less bits before reaching end of image)  
    dataLimit = floor(((len(pixList))*3)/8) - ceil(((startOffset*3)/8))
     
    #Un-comment line below to display input (uncoded yet) image
    #image.show()

    #Secret binary word is input by the user. Message displays max characters allowed taking into account
    #input image and start offset. Inputter message is converted straight away to a binary representation.
    secretBW = toBinary(input("Enter a secret message of {} characters or less:  ".format(floor(dataLimit/8))))
    
    #Loop to keep asking user for shorter message if they enter one longer than there is capacity for
    while len(secretBW) > int(dataLimit):
        print('Message too long!')
        secretBW = toBinary(input('Try again with a shorter message: '))
        print("secretBW is {} chars long".format(len(secretBW)/8))

    #Use of padder function to add 5, 4 or 3 additional hash characters to secret word to confirm end of message and also
    # make its length in binary exactly divisible by three (for easier use with pixels). 
    hBW = toBinary(padder(len(secretBW)/3))
    secretBW += hBW

    #Calculate number of pixels needed for the secret binary word (given each pixel can hold 3 bits of of the data 
    # we want to encode)
    pixNeeded = int((len(secretBW)/3))
    #Add 11 pixels to account for 'header' message containing size of message details
    pixNeeded += 11
    #Using text formatting to give us 32 bit binary representation
    binary32bPN = '{:032b}'.format(pixNeeded)
    #Printing information: pixels used to encode message
    print("Encoded Pixels Needed value: " + str(int(binary32bPN, 2)))
    #adding on extra bit to make 33bits into 33bits so divisible by 3 (and therefore go exactly into 11 pixels)
    binary32bPN += "0" 
    
    #Add secret word onto message size header
    binary32bPN += secretBW
    #Assign complete message to be encoded back to secretBW string
    secretBW = binary32bPN

    #split image into red, green & blue channels Image objects
    r,g,b = image.split()
    #Call getdata() function on r, g & b Image objects and cast into easier indexable lists
    r = list(r.getdata())
    g = list(g.getdata())
    b = list(b.getdata())
   
    #Setting up lists to hold each individula modified pixels set as well as complete pixel set 
    # containing encoded pixels
    newPixels = []
    newPixList = []
    #Counter j to help iterate through binary characters of secret message word
    j=0
    #Iterate through pixel by pixel (the number of which has been rpeviously calculated)
    for i in range(startOffset, startOffset + pixNeeded):
        #Create temporary ChanByte objects for each colour channel to store current binary 
        # number in an easily indexable list
        rChanByte = list(toBinary(int(r[i])))
        gChanByte = list(toBinary(int(g[i])))
        bChanByte = list(toBinary(int(b[i])))
        
        #Access the LSB for each channel of pixel then replace it with a binary bit of the secret word
        rChanByte[-1] = secretBW[j]
        gChanByte[-1] = secretBW[j+1]
        bChanByte[-1] = secretBW[j+2]
        j+=3
        #newPix is each of the new bytes joined into lists for each pixel
        newPix = [int(join(rChanByte), 2), int(join(gChanByte), 2), int(join(bChanByte), 2)]
        #lists are converted into tuples...
        pixTup = tuple(newPix)
        #...and tuples are added to a list
        newPixels += (pixTup,)
    #a newPixList list will contain all the elements of the new, encoded image.
    #first the unchanged pixels from first indexes up to the offset
    newPixList += pixList[0:startOffset]
    
    #then we add the newly encoded pixels (newPixels)
    newPixList += newPixels
    #finally the unchanged pixels from after those we changed up until end of the image
    newPixList += pixList[(startOffset + len(newPixels)):]
    #New Pil Image object created with same mode and size as original.
    image2 = Image.new(image.mode, image.size)
    #Newly constructed pixel list is then applied to new blank image using putdata() function
    image2.putdata(newPixList)
    #Save encoded image
    image2.save(outputFilename)
    #un-comment line below to display encoded image
    #image2.show()

# decode() function takes encoded image and reads binary message stored in LSB
def decode(inputImage, startOffset):
    #Open coded image
    codedImage = Image.open(inputImage)
    #split image into red, green & blue channels Image objects
    r,g,b = codedImage.split()
    #Call getdata() function on Image objects and cast into indexable lists
    r = list(r.getdata())
    g = list(g.getdata())
    b = list(b.getdata())
    # Code below is to read size of secret string message which occupies first 11 pixels
    #Create an empty list (numOfPixelsBin) to be populated with binary bits as we iterate through pixels below
    numOfPixelsBin = []
    #Iterate through pixel by pixel (11 is size (in pixels) of message size header)
    for i in range(startOffset, startOffset + 11):
        #Read each red, green & blue value and store as binary byte
        rByte = toBinary(r[i])
        gByte = toBinary(g[i])
        bByte = toBinary(b[i])
        #add the last indexs (our LSBs) of each binary bit to the numOfPixelsBin
        numOfPixelsBin += rByte[-1]
        numOfPixelsBin += gByte[-1]
        numOfPixelsBin += bByte[-1]
    # Join all elements of list togther into one string
    binPix = join(numOfPixelsBin)
    # Remove last bit of 33 bits to leave us with 32 bit integer we are looking for
    binPix = binPix[:-1]

    # decodedPixNeeded stores integer value of number of pixels worth of secret data we have. 
    # This is needed to now decode main message
    decodedPixNeeded = int(binPix,2)
    # Print confirmation of decoded message size
    print("Decoded Pixels Needed value: " + str(decodedPixNeeded))

    # Empty list set up to store main message bits into as they are being read through
    secretMessageBin = []

    # Iterate through each pixel containing secret data (adding 11 to startOffset to skip the message size header)
    for i in range((startOffset+11), (startOffset + decodedPixNeeded)):
        # Store each r, g, b value as a binary byte representation in a string
        rByte = toBinary(r[i])
        gByte = toBinary(g[i])
        bByte = toBinary(b[i])
        # Add the last index (LSB) of each of these to the secretMessageBin list
        secretMessageBin += rByte[-1]
        secretMessageBin += gByte[-1]
        secretMessageBin += bByte[-1]
    #Join the seperate list elements together to give us a single string containing secret message in binary form
    fullSecretMessageBin = join(secretMessageBin)
    #Convert to human readable string and print
    humanReadableSecretMessage = ''.join(chr(int(fullSecretMessageBin[i:i+8], 2)) for i in range(0, len(fullSecretMessageBin), 8))
    print("Decoded secret message: " + humanReadableSecretMessage)

"""
Various utility functions for use in encode and decode functions
"""
#To-binary converter function which can take a string or integer as input and return string binary equivalent
def toBinary(input):
    # isinstance() matches if input is string and returns string formatted in binary
    if isinstance(input, str):
        return ''.join([format(ord(i), "08b") for i in input])
    # isinstance() matches with integer input here and returns binary string containing binary representation
    elif isinstance(input, int):
        return format(input, "08b")
#ceil() function returns next integer counting up from floating point number
def ceil(input):
    # int() function cuts off number after decimal point (like a floor function) so if this number is smaller 
    # than input then take floor and add on one to return the ceiling
    if input > int(input):
        return int(input)+1
    #this else accounts for any float number with .0
    else:
        return int(input)
#floor() function essentially cuts off any numbers after decimal point and returns integer
def floor(input):
    # Logic similar to above with ceil function. Here we use int()'s coincidental floor functionality
    if input > int(input):
        return int(input)
    else:
        return int(input)
# padder() function takes input of number divided by three and, depending on the remainder value,
# adds hash characters to message which ensures message length is divisible by 3 to make it easier to work with pixels
#  which are in tuples of 3s (can avoid unexpected data being read from binary)
def padder(input):
    if (input - int(input)) > 0.5:
        return "#####"
    if (0.2 < (input - int(input)) < 0.4):
        return "####"
    else:
        return "###"
#join function to join characters stored, as separate elements in a list, to a single string
def join(list):
    # Define empty string newString
    newString = ""
    # Loop through elements of list, appending each to the newString then return as the single string
    for item in list:
        newString += item
    return newString
#Encode function takes the secret binary word and encodes to "Encoded_Image.bmp"

"""
'main' entry point to program
"""

if __name__ == "__main__":
    # startOffset value is how many pixels in to the image the secret message will start. Then the first 32 bits of 
    # message are a 32 bit integer binary representation containing the message size (in pixels)
    # To test program behaviour when message is over capacity, use IMAGE_2.bmp (approx 2mb) with a startOffset 
    # value of 701675 (switch commented lines below) which should give a payload capacity of 3 characters. 
    # Going above this limit will give error   
     
    #startOffset = 701675
    startOffset = 100    

    # Call encode() function with 3 arguments:
    # 1. Name of existing picture to be used as cover image
    # 2. Integer start offset value (as above)
    # 3. Name you want for encoded image (will overwrite any exising files of this name)
    encode("IMAGE_02.bmp", startOffset, "Encoded_Image.bmp")
    
    # Call decode() function with name of encoded image and start offset
    decode("Encoded_Image.bmp", startOffset)
