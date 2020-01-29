from fpdf import FPDF

from Utils.CommonUtil import get_current_datetime_for_report_format, get_current_datetime_for_filename_format


class PeniotPDF(FPDF):

    TITLE = 'PENIOT: Penetration Testing Tool for IoT'
    COPYRIGHT = 'Copyright ' + chr(169) + ' 2018 - 2019 PENIOT Group. All Rights Reserved.'

    def header(self):
        self.set_font('Arial', 'B', 16)

        # Add an address
        self.cell(0, 15, self.TITLE, ln=1, align='C')
        # Line break
        self.ln(15)
        self.line(0, 35, self.w, 35)

    def footer(self):
        self.set_y(-10)
        self.set_font('Arial', size=9)
        page = 'Page ' + str(self.page_no())
        self.cell(0, 5, self.COPYRIGHT, 0, 0, 'C', 0)
        self.cell(0, 5, page, 0, 0, 'R')

    def add_title_and_date(self, attack_name):
        self.set_font("Arial", size=14, style='B')
        self.cell(0, 5, attack_name + ' Summary', 0, 0, 'L')
        self.set_font("Arial", size=12)
        self.cell(0, 5, 'Date: ' + get_current_datetime_for_report_format(), 0, 0, 'R')
        self.ln(10)

    def add_attack_logs(self, attack_logs):
        self.set_font("Arial", size=12)
        self.multi_cell(0, 5, txt=attack_logs)


class GenerateReport(object):

    @staticmethod
    def generate_pdf_from_text(protocol_name, attack_name, attack_logs, directory):
        pdf = PeniotPDF()
        pdf.add_page()

        pdf.add_title_and_date(attack_name)
        pdf.add_attack_logs(attack_logs)

        output_name = ('_'.join((protocol_name + ' ' + attack_name).split())).lower()
        pdf.output(directory + output_name + '_' + get_current_datetime_for_filename_format())


if __name__ == '__main__':
    txt = """
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras quis lacus varius, tempus odio vitae, tempor enim. Cras ut nibh justo. Ut diam ipsum, interdum commodo orci non, ultrices dictum magna. Curabitur tortor lacus, finibus et mattis nec, malesuada nec nibh. Morbi nec sem a leo tincidunt viverra quis eget leo. Aliquam erat volutpat. In tempor auctor tincidunt. Aliquam lectus dui, semper vel justo a, molestie tristique magna. Mauris nec vulputate sapien, blandit convallis felis. In a orci vel urna vehicula faucibus quis et mi. Duis lacus magna, malesuada eu mattis vestibulum, interdum vitae lectus. Lorem ipsum dolor sit amet, consectetur adipiscing elit.

    Suspendisse a lectus id nibh semper hendrerit non eget nisi. Maecenas massa magna, euismod ac dui et, tristique porta metus. Maecenas sed massa eget leo commodo sagittis iaculis ac nisi. Suspendisse ullamcorper, purus quis faucibus venenatis, metus mauris faucibus turpis, ac posuere magna velit non est. Ut ac odio vitae ante ultricies aliquam. Quisque sapien sem, condimentum at erat nec, luctus facilisis nisl. Sed maximus velit ac pellentesque sagittis. Donec ac sagittis leo, et laoreet sem. Vivamus egestas lectus non bibendum accumsan. Sed tempus risus id odio volutpat, a ullamcorper odio lacinia. In vitae velit nulla. Praesent a venenatis diam, a vestibulum tortor.
    
    Duis tincidunt efficitur faucibus. Praesent eget dui tellus. Vestibulum dapibus aliquam arcu. Donec vulputate sem enim, quis tincidunt diam blandit ut. Curabitur accumsan maximus risus, sed dictum ligula volutpat vitae. Curabitur convallis ac mauris ut consectetur. Quisque tellus arcu, ultrices vel ante quis, aliquet fringilla mauris. Sed ornare eros sed interdum facilisis. Duis dictum augue vel rutrum maximus. Phasellus neque dolor, pretium non risus in, tincidunt feugiat eros. Integer vel odio iaculis, faucibus neque quis, mollis enim. Etiam ac euismod orci. Donec tempor, erat at cursus porta, tortor sem aliquam leo, eget porta erat libero eu enim. Etiam felis elit, consectetur a facilisis id, porta quis nulla. Quisque libero odio, ultrices quis est et, efficitur pellentesque dui.
    
    Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Praesent semper tempus risus, eu condimentum leo interdum sed. Aenean turpis leo, aliquet non ligula venenatis, fermentum maximus velit. Aliquam aliquam posuere libero, quis cursus nisl gravida quis. Proin ac interdum lorem, vitae varius lacus. Maecenas sit amet convallis leo, sit amet tincidunt enim. Suspendisse sit amet risus sit amet libero aliquam mollis. Vestibulum vehicula lacus condimentum, fermentum turpis id, pretium eros. Cras sagittis sem nec porta dictum. Donec a accumsan dolor. Nam dictum eros at leo viverra, ac mattis elit placerat. Mauris ornare pulvinar massa nec rutrum. Nunc nec erat at est lobortis dictum ut in enim. Donec eu est sit amet lacus feugiat blandit. Praesent a sollicitudin ex, blandit fermentum tellus. Nulla vitae viverra ipsum, in pharetra dolor.
    
    Praesent imperdiet nec nisi aliquam dictum. Nunc ultricies sodales porta. Donec consectetur finibus tellus, porttitor sodales sapien pulvinar in. Duis suscipit suscipit felis eu luctus. Nam in dolor aliquam, laoreet elit a, faucibus ligula. Nulla quis nisl imperdiet dolor molestie rhoncus. Fusce neque tortor, blandit at sapien in, egestas fermentum felis. Curabitur auctor ipsum vitae velit vestibulum ultrices.
    
    Pellentesque eget lectus urna. Aenean commodo semper orci sit amet dictum. Curabitur ultrices vitae ipsum in bibendum. Nunc at justo ut augue mollis aliquam. Sed varius, purus at sagittis condimentum, ex velit elementum neque, at malesuada dui arcu nec orci. Nullam viverra, nisi aliquam porta tempor, ex ex bibendum eros, eu viverra urna turpis eu massa. Vestibulum quam lectus, ullamcorper sit amet imperdiet in, tincidunt quis tortor.
    
    Sed non mollis ligula, non imperdiet nunc. Nam elementum augue sit amet risus pulvinar, id dapibus velit laoreet. Sed commodo arcu ut tellus commodo, sed gravida nisl viverra. Sed non sapien lacus. Etiam nec gravida urna, vitae sodales risus. Donec iaculis vel ex aliquam imperdiet. Maecenas condimentum imperdiet porta. Suspendisse potenti. Donec tincidunt vestibulum libero, ac lobortis nisi interdum ac. Curabitur luctus nisl a lorem ultrices pellentesque. Nam eleifend at ex nec pretium. Nullam id purus eget metus facilisis condimentum quis non urna. Quisque et volutpat purus. Pellentesque facilisis molestie orci, a pharetra dolor aliquet sed.
    
    Vestibulum purus mi, dapibus ac rutrum et, convallis at magna. Nunc leo justo, finibus quis molestie vel, accumsan sit amet diam. Quisque vehicula lacus vitae augue imperdiet vulputate. Phasellus vulputate metus vel ex dapibus, nec pretium sapien eleifend. Cras metus erat, vehicula sed mi ut, eleifend finibus dui. Mauris bibendum, velit vel mollis sodales, libero orci congue dui, non dapibus eros lectus malesuada tortor. Ut dignissim dui turpis, ut faucibus velit consectetur nec. Aenean vestibulum turpis pulvinar egestas fringilla. Suspendisse potenti. Etiam dignissim sapien ac velit molestie, ac blandit augue tempor. Pellentesque laoreet tellus a dui dignissim, eget sagittis lacus pharetra. Sed id elit ac lorem tristique cursus. Nunc vel porta augue. Lorem ipsum dolor sit amet, consectetur adipiscing elit.
    
    Donec at dolor eget arcu dignissim mollis at eget erat. Aenean sodales enim id massa vehicula, ac tempus massa dictum. Praesent facilisis id urna vel scelerisque. Etiam pharetra consequat massa eget molestie. Donec ullamcorper ipsum ut orci aliquet placerat. Quisque sit amet magna quis velit tincidunt placerat. Nulla facilisi. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Duis congue est sit amet arcu sollicitudin dapibus. Maecenas tristique venenatis ante, eu elementum leo sollicitudin vel.
    
    Suspendisse at accumsan nulla. Nam blandit auctor purus posuere tempor. Pellentesque molestie pellentesque justo ut condimentum. Aenean non fringilla mi. Nullam elementum nibh orci, eget imperdiet eros elementum hendrerit. Nam vitae volutpat odio. Pellentesque a ligula iaculis odio varius porta at ut ipsum.
    
    Nulla mi augue, malesuada iaculis nibh sed, blandit molestie enim. Donec luctus ipsum sed mollis porta. Nam hendrerit finibus turpis, ac elementum ante mattis vel. Aliquam tincidunt varius tellus sed tempus. Fusce vel tellus sem. Sed suscipit ex in auctor dictum. Duis ullamcorper tortor urna, non ullamcorper justo convallis ac. Nullam at est magna. Nam id erat mattis orci bibendum ultrices et in nisl. Maecenas a fringilla lorem. In facilisis, sapien volutpat posuere consectetur, ligula erat ornare neque, a ornare velit.
    """
    GenerateReport.generate_pdf_from_text('CoAP', 'DoS Attack', txt)
