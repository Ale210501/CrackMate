FROM kalilinux/kali-rolling

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-tk \
        python3-pil python3-pil.imagetk \
        aircrack-ng hashcat hcxtools iproute2 iw sudo \
        adb \
        git curl wget \
        && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all project files
COPY . /app

# Set environment variables for Tkinter (avoid root errors)
ENV MPLBACKEND=Agg
ENV DISPLAY=:0

# Allow passwordless sudo for root (and optionally for a user if needed)
RUN echo "root ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Default command (can be overridden)
CMD ["python3", "Script5.py"]
