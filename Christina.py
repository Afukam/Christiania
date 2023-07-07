import argparse
import csv
import nmap
from fpdf import FPDF
import sendgrid
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
import concurrent.futures


def scan_url(url):
    scanner = nmap.PortScanner()
    scanner.scan(url, arguments='-sV --script vulners')
    return scanner.csv()


def scan_target(target):
    scan_results = scan_url(target)
    open_ports = []
    services = []
    vulnerabilities = []

    # Parse CSV scan results
    csv_lines = scan_results.strip().split('\n')
    reader = csv.DictReader(csv_lines)

    for row in reader:
        port = row.get('port')
        service = row.get('service')
        vulnerability = row.get('vulnerability')

        if port and service:
            open_ports.append(int(port))
            services.append(service)

        if vulnerability:
            vulnerabilities.append(vulnerability)

    return target, open_ports, services, vulnerabilities


def create_pdf(scan_results):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, "Vulnerability Scan Results", ln=True)
    pdf.ln(10)

    for result in scan_results:
        target, open_ports, services, vulnerabilities, *_ = result
        pdf.cell(0, 10, f"Target: {target}", ln=True)
        pdf.cell(0, 10, f"Open Ports: {', '.join(map(str, open_ports))}", ln=True)
        pdf.cell(0, 10, f"Services: {', '.join(services)}", ln=True)
        pdf.cell(0, 10, f"Vulnerabilities: {', '.join(vulnerabilities)}", ln=True)
        pdf.ln(10)

    pdf_file = "scan_results.pdf"
    pdf.output(pdf_file)
    return pdf_file


def send_email(api_key, sender, recipient, subject, body, attachment_file):
    message = Mail(
        from_email=sender,
        to_emails=recipient,
        subject=subject,
        plain_text_content=body
    )

    with open(attachment_file, 'rb') as f:
        data = f.read()
        f.close()

    encoded_file = FileContent(content=data)
    attached_file = Attachment(
        file_content=encoded_file,
        file_name=FileName(attachment_file),
        file_type=FileType('application/pdf'),
        disposition=Disposition('attachment')
    )
    message.attachment = attached_file

    sg = sendgrid.SendGridAPIClient(api_key=api_key)
    response = sg.send(message)
    print(response.status_code)


def main():
    parser = argparse.ArgumentParser(description='Vulnerability Scan Tool by Abraham E. Tanta')
    parser.add_argument('-t', '--target', help='IP or URL to scan')
    parser.add_argument('-f', '--target-file', help='Path to target.txt file')
    parser.add_argument('-k', '--sendgrid-api-key', help='SendGrid API key')
    parser.add_argument('-s', '--sender-email', help='Sender email address')
    parser.add_argument('-r', '--recipient-email', help='Recipient email address')
    args = parser.parse_args()

    if args.target:
        target = args.target
        scan_results = scan_target(target)
        pdf_file = create_pdf(scan_results)

        if args.sendgrid_api_key and args.sender_email and args.recipient_email:
            send_email(args.sendgrid_api_key, args.sender_email, args.recipient_email, 'Vulnerability Scan Results',
                       'Please find the scan results attached.', pdf_file)
        else:
            print("Email functionality skipped. Email arguments are missing.")

    elif args.target_file:
        target_file = args.target_file
        with open(target_file, 'r') as file:
            targets = file.read().splitlines()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            scan_results = list(executor.map(scan_target, targets))
            pdf_file = create_pdf(scan_results)


            if args.sendgrid_api_key and args.sender_email and args.recipient_email:
                send_email(args.sendgrid_api_key, args.sender_email, args.recipient_email, 'Vulnerability Scan Results',
                           'Please find the scan results attached.', pdf_file)
            else:
                print("Email functionality skipped. Email arguments are missing.")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
