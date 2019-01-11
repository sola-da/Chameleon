=begin
module to hide a message in the alpha channel of a PNG image.
the code is based on:
https://www.peter-eigenschink.at/projects/steganographyjs/
ported from JavaScript to Ruby by Saeed Ehteshamifar (salpha.2004@gmail.com)
Autumn 2017
=end

require 'chunky_png'

module Steganography

  include ChunkyPNG
  
  # returns the image object with the message hidden in it
  def Steganography.encode(message)
    # an image of size w*h can hide t*w*h/codeUnitSize chars,
    # t is hardcoded to 3, codeUnitSize is hardcoded to 16,
    # we take a factor of 4 in both minimum_width and minimum_height,
    # =>
    minimum_image_width = Math.sqrt(message.length / 3).ceil * 4
    # make a square image.
    minimum_image_height = minimum_image_width

    # we create an image with the minimum size that's just enough to hide the message
    # because the decoding would be faster with smaller images.
    img = Image.new(minimum_image_width, minimum_image_height, Color::TRANSPARENT)

    img_str = img.to_rgba_stream.chars
    img_data = []
    img_str.each do |ch|
      img_data.push(ch.ord)
    end

    t = 3
    codeUnitSize = 16
    bundlesPerChar = codeUnitSize / t >> 0
    overlapping = codeUnitSize % t
    modMessage = []
    oldDec = 0

    for i in (0..message.length)
      # stupid conditional while translating from stupid JS to elegant Ruby!
      if (i == message.length)
        dec = 0
      else
        dec = message[i].ord || 0;
      end
      
      curOverlapping = (overlapping * i) % t
      if (curOverlapping > 0 && oldDec)
        # Mask for the new character, shifted with the count of overlapping bits
        mask = (2 ** (t - curOverlapping)) - 1
        # Mask for the old character, i.e. the t-curOverlapping bits on the right of that character
        oldMask = ((2 ** codeUnitSize) * (1 - (2 ** -curOverlapping).to_f)).to_i
        left = (dec & mask) << curOverlapping
        right = (oldDec & oldMask) >> (codeUnitSize - curOverlapping)
        modMessage.push(left + right)

        if (i < message.length)
          mask = ((2 ** (2 * t - curOverlapping)).to_f * (1 - (2 ** -t).to_f)).to_i
          for j in (1..bundlesPerChar-1)
            decM = dec & mask
            modMessage.push(decM >> (((j - 1) * t) + (t - curOverlapping)))
            mask <<= t
          end
          if ((overlapping * (i + 1)) % t === 0)
            mask = ((2 ** codeUnitSize) * (1 - (2 ** -t).to_f)).to_i
            decM = dec & mask
            modMessage.push(decM >> (codeUnitSize-t))
          elsif ((((overlapping * (i + 1)) % t) + (t - curOverlapping)) <= t)
            decM = dec & mask
            modMessage.push(decM >> (((bundlesPerChar - 1) * t) + (t - curOverlapping)))
          end
        end
      elsif (i < message.length)
        mask = (2 ** t) - 1
        for j in (0..bundlesPerChar - 1)
          decM = dec & mask
          modMessage.push(decM >> (j * t))
          mask <<= t
        end
      end
      oldDec = dec
    end

    # Write Data
    prime = 11
    subOffset = 0
    for offset in (0..modMessage.length - 1)
      if ((offset + 1) * 4 > img_data.length)
        break
      end

      qS=[]

      if (offset < modMessage.length)
        q = 0;
        q += modMessage[offset]
        qS[0] = (255 - prime + 1) + (q % prime)
      end

      for i in (offset * 4..((offset + qS.length) * 4) - 1).step(4)
        if (i >= img_data.length)
          break
        end
        img_data[i + 3] = qS[0]
      end

      subOffset = qS.length;
    end


    # Write message-delimiter
    delimiter = [255, 255, 255]
    for index in (offset + subOffset..delimiter.length + offset + subOffset - 1)
      if ((offset + delimiter.length) * 4 >= img_data.length)
        break
      end
      img_data[(index * 4) + 3] = delimiter[index - (offset + subOffset)]
    end

    # Clear remaining img_data
    for i in ( ((index + 1) * 4 + 3)..(img_data.length - 1) ).step(4)
      img_data[i] = 255
    end

    pixel_size = 4 # 4 = rbga
    for y in 0..img.height-1
      for x in 0..img.width-1
        base = (y * img.width * pixel_size) + (x * pixel_size)
        img[x, y] = Color.rgba(img_data[base], img_data[base+1], img_data[base+2], img_data[base+3])
      end
    end

    return img
  end

end
