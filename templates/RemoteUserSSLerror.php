<?php

use SimpleSAML\Utils\HTTP;

$this->data['header'] = $this->t('{remoteuserssl:RemoteUserSSLerror:header}');

$this->includeAtTemplateBase('includes/header.php');

if (isset($this->data['errorcode']) && $this->data['errorcode'] !== null) {
    ?>
    <div class="alert alert-warning">
        <p><strong><?php echo $this->t('{login:error_header}'); ?></strong></p>
        <p><b><?php echo $this->t($this->data['errorcodes']['title'][$this->data['errorcode']]); ?></b></p>
        <p><?php echo $this->t($this->data['errorcodes']['descr'][$this->data['errorcode']]); ?></p>
    </div>
    <?php
} else {
    ?>
    <div class="alert alert-warning">
        <p><strong><?php echo $this->t('{remoteuserssl:RemoteUserSSLerror:header}'); ?></strong></p>
        <p><?php echo $this->t('{remoteuserssl:RemoteUserSSLerror:text}'); ?></p>

    </div>
    <?php
}
if (!empty($this->data['links'])) {
    echo '<ul class="links" style="margin-top: 2em">';
    foreach ($this->data['links'] as $l) {
        echo '<li><a href="' . htmlspecialchars($l['href']) . '">' . htmlspecialchars($this->t($l['text'])) .
            '</a></li>';
    }
    echo '</ul>';
}

$this->includeAtTemplateBase('includes/footer.php');
