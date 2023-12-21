import cv2
import numpy as np
class ImageSteganographyUtil:
    @staticmethod
    def msg_to_bin(msg):
        if type(msg) == str:
            return ''.join([format(ord(i), "08b") for i in msg])
        elif type(msg) == bytes or type(msg) == np.ndarray:
            return [format(i, "08b") for i in msg]
        elif type(msg) == int or type(msg) == np.uint8:
            return format(msg, "08b")
        else:
            raise TypeError("[-] Input type not supported")

    @staticmethod
    def insert_data(secret_msg):
        while True:
            img_name = './example_images_for_stego/' + input('Enter the name of the image to use to hide data (with extension): ')
            print('[+] Trying to read image from:', img_name)
            img = cv2.imread(img_name)
            if img is not None:
                print('[+] Image read successfully.')
                nBytes = img.shape[0] * img.shape[1] * 3 // 8
                print('[+] Maximum Bytes for encoding:', nBytes)
                if len(secret_msg) > nBytes:
                    print('[-] Error encountered insufficient bytes, need bigger image or less data!')
                else: 
                    break 
            else:
                print('[-] Unable to read the image. Please check the file path and try again.')
             
        file_name = './alice_data/' + input('Give a name for encoded image:(no need extension) ') + '.png'
        secret_msg += '#####'
        dataIndex = 0
        bin_secret_msg = ImageSteganographyUtil.msg_to_bin(secret_msg)

        dataLen = len(bin_secret_msg)
        for values in img:
            for pixels in values:
                r, g, b = ImageSteganographyUtil.msg_to_bin(pixels)
                if dataIndex < dataLen:
                    pixels[0] = int(r[:-1] + bin_secret_msg[dataIndex], 2)
                    dataIndex += 1
                if dataIndex < dataLen:
                    pixels[1] = int(g[:-1] + bin_secret_msg[dataIndex], 2)
                    dataIndex += 1
                if dataIndex < dataLen:
                    pixels[2] = int(b[:-1] + bin_secret_msg[dataIndex], 2)
                    dataIndex += 1
                if dataIndex >= dataLen:
                    break

        cv2.imwrite(file_name, img)
        print('[+] New encoded image created at ' + file_name)
        return file_name

    @staticmethod
    def extract_data(img_path):
        print('[+] Extracting data from ' + img_path)
        img = cv2.imread(img_path)
        bin_data = ""
        for values in img:
            for pixels in values:
                r, g, b = ImageSteganographyUtil.msg_to_bin(pixels)
                bin_data += r[-1]
                bin_data += g[-1]
                bin_data += b[-1]

        allBytes = [bin_data[i: i + 8] for i in range(0, len(bin_data), 8)]
        decodedData = ""
        for my_bytes in allBytes:
            decodedData += chr(int(my_bytes, 2))
            if decodedData[-5:] == "#####":
                break

        return decodedData[:-5]
