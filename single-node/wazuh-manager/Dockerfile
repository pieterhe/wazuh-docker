FROM wazuh/wazuh-manager:4.14.4

# Copy patch scripts into the image
COPY patch_templates.py /tmp/patch_templates.py
COPY patch_pipeline.py /tmp/patch_pipeline.py

# Run both patches at build time
RUN python3 /tmp/patch_templates.py && \
    python3 /tmp/patch_pipeline.py && \
    rm /tmp/patch_templates.py /tmp/patch_pipeline.py
