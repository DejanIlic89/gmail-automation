package google.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MailQuery {
    private String label;
    private String subject;
    private String sender;
    private String receiver;
}
