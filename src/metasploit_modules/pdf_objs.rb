=begin
module to handle creation of various PDF object (e.g. XFA) using Origami-PDF
Author: Saeed Ehteshamifar (salpha.2004@gmail.com)
Autumn 2017
=end

require 'origami' # required for SampleXDP and apply_evasion_make_pdf
require 'origami/template/widgets'

module PDFObj

  include Origami
  using Origami::TypeConversion

  def PDFObj.pdf_add_objs(pdf, args, js, objs)
    objs.each do |obj|
      if (obj.keys.first.casecmp("xfa") == 0) # each dictionary has only one key (-> 'first')
        # add the XFA form that's needed for adobe_toolbutton exploit module
        ml = Template::MultiLineEdit.new('TextField1[0]', x: 50, y: 280, width: 500, height: 400)
        button = Template::Button.new('Send!', id: 'Button1[0]', x: 490, y: 240, width: 60, height: 30)
        form1 = Field::Subform.new(T: "form1[0]")
        form1.add_fields(subform = Field::Subform.new(T: "#subform[0]"))
        subform.add_fields(ml, button)
        xdp = SampleXDP.new('').to_s
        pdf.create_xfa_form(xdp, form1)
      end
      if (obj.keys.first.casecmp("font") == 0) # each dictionary has only one key (-> 'first')
        font_file = Stream.new(obj["font"],
          :Filter => :FlateDecode,
          :Length1 => obj["font"].length
        )
        font_descriptor = FontDescriptor.new(
          :FontName => :Cinema,
          :Flags => 131140,
          :FontBBox => [-177, -269, 1123, 866],
          :FontFile2 => font_file,
        ).to_o
        font_obj = Font::TrueType.new(
          :Subtype => :TrueType,
          :BaseFont => :Cinema,
          :Widths => [],
          :FontDescriptor => font_descriptor,
        ).to_o
        font_declaration = {:F1 => font_obj}.to_o
        resources = Resources.new(:Font => font_declaration)
        pdf.append_page(Page.new(:Resources => resources))
        #pdf.pages.first.Resources=(resources) -> will crash since the content of the first page make the font file be processed
      end
    end
    pdf.onDocumentOpen(Action::JavaScript js)
    return pdf
  end

  #
  # XDP Packet holding the Form.
  # taken from origami (https://github.com/gdelugre/origami/blob/master/examples/forms/xfa.rb)
  #
  class SampleXDP < Origami::XDP::Package

    include Origami

    def initialize(script = "")
      super()
      self.root.add_element(create_config_packet)
      self.root.add_element(create_template_packet(script))
      self.root.add_element(create_datasets_packet)
    end

    def create_config_packet
      config = XDP::Packet::Config.new
      present = config.add_element(XFA::Element.new("present"))
      pdf = present.add_element(XFA::Element.new("pdf"))
      interactive = pdf.add_element(XFA::Element.new("interactive"))
      interactive.text = 1
      config
    end

    def create_template_packet(script)
      template = XDP::Packet::Template.new
      form1 = template.add_subform(layout: 'tb', name: 'form1')
      form1.add_pageSet
      form1.add_event(activity: 'initialize', name: 'event__ready')
           .add_script(contentType: 'application/x-formcalc')
           .text = script
      subform = form1.add_subform
      button = subform.add_field(name: 'Button1')
      button.add_ui.add_button(highlight: 'inverted')
      btncaption = button.add_caption
      btncaption.add_value.add_text.text = "Send!"
      btncaption.add_para(vAlign: 'middle', hAlign: 'center')
      button.add_bind(match: 'none')
      button.add_event(activity: 'click', name: 'event__click')
            .add_script(contentType: 'application/x-formcalc')
            .text = script
      txtfield = subform.add_field(name: 'TextField1')
      txtfield.add_ui.add_textEdit.add_border.add_edge(stroke: 'lowered')
      template
    end

    def create_datasets_packet
      datasets = XDP::Packet::Datasets.new
      data = datasets.add_element(XDP::Packet::Datasets::Data.new)
      data.add_element(XFA::Element.new('form1'))
          .add_element(XFA::Element.new('TextField1'))
          .text = '$host.messageBox("Greetings from Mars!")'
      datasets
    end
  end

end
