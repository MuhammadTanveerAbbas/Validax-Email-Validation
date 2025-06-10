window.addEventListener('DOMContentLoaded', () => {
  (function initEmailValidation() {
    const form = document.getElementById('emailForm');
    const resultCont = document.getElementById('resultCont');
    if (!form || !resultCont) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault(); 
      const validateBtn = document.getElementById('validateBtn');
      validateBtn.disabled = true;
      resultCont.innerHTML = '<img src="assets/images/loading.svg" width="40" alt="Loading...">';

      const emailInput = document.getElementById('username');
      const email = emailInput ? emailInput.value.trim() : '';
      const apiKey = 'write here'; // Replace with your actual API key from emailvalidation.io
      const url = `https://api.emailvalidation.io/v1/info?apikey=${apiKey}&email=${encodeURIComponent(email)}`;

      try {
        const res = await fetch(url);
        if (!res.ok) {
          throw new Error(`API Error: ${res.statusText}`);
        }

        const data = await res.json();
        resultCont.innerHTML = `
          <div class="result-grid">
            <div class="result-item"><span>Valid:</span> ${data.format_valid ? 'Yes' : 'No'}</div>
            <div class="result-item"><span>Deliverable:</span> ${data.state === 'deliverable' ? 'Yes' : 'No'}</div>
          </div>`;
      } catch (error) {
        console.error('Error:', error);
        resultCont.innerHTML = '<div class="result-item error">Error: Unable to validate email.</div>';
      } finally {
        validateBtn.disabled = false;
      }
    });
  })();

  // === Copy Email Button ===
  (function initCopyEmail() {
    const copyBtn = document.getElementById('copyButton');
    if (!copyBtn) return;

    let copyMsg = document.getElementById('copyMessage');
    if (!copyMsg) {
      copyMsg = document.createElement('div');
      copyMsg.id = 'copyMessage';
      copyMsg.className = 'message';
      copyMsg.textContent = 'Email copied to clipboard!';
      copyBtn.insertAdjacentElement('afterend', copyMsg);
    }

    copyBtn.addEventListener('click', () => {
      const emailAddr = 'muhammadtanveerabbas.dev@gmail.com';

      navigator.clipboard?.writeText(emailAddr)
        .catch(() => {
          const tmp = document.createElement('input');
          tmp.value = emailAddr;
          document.body.appendChild(tmp);
          tmp.select();
          document.execCommand('copy');
          document.body.removeChild(tmp);
        })
        .finally(() => {
          copyBtn.textContent = 'Copied!';
          copyBtn.classList.add('clicked');
          copyMsg.classList.add('visible');

          setTimeout(() => {
            copyBtn.textContent = 'Copy Email';
            copyBtn.classList.remove('clicked');
            copyMsg.classList.remove('visible');
          }, 3000);
        });
    });
  })();

});
