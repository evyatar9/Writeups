import binascii

leftTopCorners = []
rightTopCorners = []
leftBottomCorners = []
rightBottomCorners = []
	
def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def getCorners(rows):
    for row in range(len(rows)):
        for col in range(len(rows[row])):
            if rows[row][col] == 0:
                if (row == 0 or rows[row-1][col] == 255) and (col == 0 or rows[row][col-1] == 255):
                    leftTopCorners.append({'row':row,'col':col})
                elif (row == 0 or rows[row-1][col] == 255) and (col == 49 or rows[row][col+1] == 255):
                    rightTopCorners.append({'row':row,'col':col})                    
                elif (row == 49 or rows[row+1][col] == 255) and (col == 0 or rows[row][col-1] == 255):
                    leftBottomCorners.append({'row':row,'col':col})
                elif (row == 49 or rows[row+1][col] == 255) and (col == 49 or rows[row][col+1] == 255):
                    rightBottomCorners.append({'row':row,'col':col})
					
def main():
    input_data_in_base64_str = open('uhoh.txt').read() #input()
    matrix = binascii.a2b_base64(input_data_in_base64_str)
    matrix = matrix[13:]
    lists = list(chunks(matrix, 180))

    for i in range(len(lists)):
     lists[i] = lists[i][0::3]


    # working area
    lists = lists[27:]
    lists = lists[:-3]
    for i in range(len(lists)):
        lists[i] = lists[i][2:52]
        lists[i] = bytearray(lists[i])


    rows = lists
    getCorners(rows)

    for lt in range(len(leftTopCorners)):
        # search for rightBottomCorner
        for rb in range(len(rightBottomCorners)):
            if rightBottomCorners[rb]['row'] > leftTopCorners[lt]['row'] and rightBottomCorners[rb]['col'] > leftTopCorners[lt]['col']:
                # Check if between all black/color
                shouldBlack = False
                for r in range(leftTopCorners[rb]['row'], rightBottomCorners[rb]['row']+1):
                    for c in range(leftTopCorners[rb]['col'], rightBottomCorners[rb]['col']+1):
                        if rows[r][c] == 255:
                            shouldBlack = True
                            break
                            
                if not shouldBlack:
                    for r in range(leftTopCorners[rb]['row'], rightBottomCorners[rb]['row']+1):
                        for c in range(leftTopCorners[rb]['col'], rightBottomCorners[rb]['col']+1):
                            rows[r][c] = 0

	# leftBottomCorners vs rightTopCorners
    for lt in range(len(leftBottomCorners)):
        # search for rightTopCorners
        for rb in range(len(rightTopCorners)):
            if rightTopCorners[rb]['row'] < leftBottomCorners[lt]['row'] and rightTopCorners[rb]['col'] > leftBottomCorners[lt]['col']:
                # Check if between all black/color

                shouldBlack = False
                for r in range(rightTopCorners[rb]['row'], leftBottomCorners[lt]['row']+1):
                    for c in range(leftBottomCorners[lt]['col'], rightTopCorners[rb]['col']+1):
                        if rows[r][c] == 255:
                            shouldBlack = True
                            break
                            
                if not shouldBlack:
                    for r in range(rightTopCorners[rb]['row'], leftBottomCorners[lt]['row']+1):
                        for c in range(leftBottomCorners[lt]['col'], rightTopCorners[rb]['col']+1):
                            rows[r][c] = 0


    ppm_header_50x50 = b'P6\n50 50\n255\n'
    all_bytes = ppm_header_50x50
	
    for i in range(len(rows[i])): # Validate all in black/white
        for j in range(len(rows[i])):
            if rows[i][j] != 0 and rows[i][j] != 255:
                rows[i][j] = 255

    for i in range(len(rows[i])):
        for j in range(len(rows[i])):
            all_bytes += bytes([rows[i][j]]) + bytes([rows[i][j]]) + bytes([rows[i][j]])

    print((binascii.b2a_base64(all_bytes)).decode("utf-8"))

main()